;; fee-access-control
;; 
;; A fee-based access control mechanism for managing data sharing and permissions
;; with flexible, secure, and auditable access management.
;;
;; This contract provides a robust system for controlling data access, 
;; implementing fee-based permissions, and maintaining a comprehensive 
;; access audit trail.

;; Error codes
(define-constant err-unauthorized u1)
(define-constant err-participant-already-exists u2)
(define-constant err-participant-does-not-exist u3)
(define-constant err-resource-already-registered u4)
(define-constant err-resource-not-registered u5)
(define-constant err-accessor-not-verified u6)
(define-constant err-accessor-already-verified u7)
(define-constant err-access-not-granted u8)
(define-constant err-invalid-resource-type u9)
(define-constant err-invalid-expiry u10)

;; Resource types
(define-constant resource-type-document "document")
(define-constant resource-type-media "media")
(define-constant resource-type-data "data")
(define-constant resource-type-service "service")

;; Data maps
(define-map participants 
  { participant: principal } 
  { registered: bool, registration-time: uint }
)

(define-map participant-resources 
  { participant: principal, resource-id: (string-ascii 64) } 
  { registered: bool, resource-type: (string-ascii 64), registration-time: uint }
)

(define-map verified-accessors
  { accessor: principal }
  { verified: bool, accessor-type: (string-ascii 64), verification-time: uint }
)

(define-map access-permissions
  { participant: principal, accessor: principal, resource-type: (string-ascii 64) }
  { granted: bool, expiry: (optional uint), grant-time: uint, fee-paid: uint }
)

(define-map access-history
  { access-id: uint }
  { 
    participant: principal, 
    accessor: principal, 
    resource-type: (string-ascii 64), 
    access-time: uint,
    purpose: (string-ascii 128),
    fee-amount: uint
  }
)

(define-data-var access-history-counter uint u0)

;; Private helper functions
(define-private (is-valid-resource-type (resource-type (string-ascii 64)))
  (or
    (is-eq resource-type resource-type-document)
    (is-eq resource-type resource-type-media)
    (is-eq resource-type resource-type-data)
    (is-eq resource-type resource-type-service)
  )
)

(define-private (is-participant-registered (participant principal))
  (default-to false (get registered (map-get? participants { participant: participant })))
)

(define-private (is-resource-registered (participant principal) (resource-id (string-ascii 64)))
  (default-to false (get registered (map-get? participant-resources { participant: participant, resource-id: resource-id })))
)

(define-private (is-accessor-verified (accessor principal))
  (default-to false (get verified (map-get? verified-accessors { accessor: accessor })))
)

(define-private (has-access (participant principal) (accessor principal) (resource-type (string-ascii 64)))
  (let ((permission (map-get? access-permissions { participant: participant, accessor: accessor, resource-type: resource-type })))
    (if (is-none permission)
      false
      (let ((permission-value (unwrap-panic permission)))
        (if (not (get granted permission-value))
          false
          (match (get expiry permission-value)
            expiry-time (< block-height expiry-time)
            true  ;; No expiry means permanent access
          )
        )
      )
    )
  )
)

(define-private (next-access-id)
  (let ((current (var-get access-history-counter)))
    (var-set access-history-counter (+ current u1))
    current
  )
)

(define-private (record-access 
  (participant principal) 
  (accessor principal) 
  (resource-type (string-ascii 64)) 
  (purpose (string-ascii 128))
  (fee-amount uint)
)
  (let ((access-id (next-access-id)))
    (map-set access-history
      { access-id: access-id }
      {
        participant: participant,
        accessor: accessor,
        resource-type: resource-type,
        access-time: block-height,
        purpose: purpose,
        fee-amount: fee-amount
      }
    )
    (ok access-id)
  )
)

;; Read-only functions
(define-read-only (check-participant-registration (participant principal))
  (ok (is-participant-registered participant))
)

(define-read-only (check-accessor-verification (accessor principal))
  (ok (is-accessor-verified accessor))
)

(define-read-only (check-access-permission (participant principal) (accessor principal) (resource-type (string-ascii 64)))
  (ok (has-access participant accessor resource-type))
)

(define-read-only (get-access-details (access-id uint))
  (ok (map-get? access-history { access-id: access-id }))
)

;; Public functions
(define-public (register-participant)
  (let ((sender tx-sender))
    (asserts! (not (is-participant-registered sender)) (err err-participant-already-exists))
    
    (map-set participants
      { participant: sender }
      { registered: true, registration-time: block-height }
    )
    
    (ok true)
  )
)

(define-public (register-resource (resource-id (string-ascii 64)) (resource-type (string-ascii 64)))
  (let ((sender tx-sender))
    (asserts! (is-participant-registered sender) (err err-participant-does-not-exist))
    (asserts! (not (is-resource-registered sender resource-id)) (err err-resource-already-registered))
    
    (map-set participant-resources
      { participant: sender, resource-id: resource-id }
      { registered: true, resource-type: resource-type, registration-time: block-height }
    )
    
    (ok true)
  )
)

(define-public (register-accessor (accessor principal) (accessor-type (string-ascii 64)))
  (let ((sender tx-sender))
    (asserts! (is-eq sender (as-contract tx-sender)) (err err-unauthorized))
    (asserts! (not (is-accessor-verified accessor)) (err err-accessor-already-verified))
    
    (map-set verified-accessors
      { accessor: accessor }
      { verified: true, accessor-type: accessor-type, verification-time: block-height }
    )
    
    (ok true)
  )
)

(define-public (grant-access 
  (accessor principal) 
  (resource-type (string-ascii 64)) 
  (expiry (optional uint))
  (fee-amount uint)
)
  (let ((sender tx-sender))
    (asserts! (is-participant-registered sender) (err err-participant-does-not-exist))
    (asserts! (is-accessor-verified accessor) (err err-accessor-not-verified))
    (asserts! (is-valid-resource-type resource-type) (err err-invalid-resource-type))
    
    (match expiry
      expiry-time (asserts! (> expiry-time block-height) (err err-invalid-expiry))
      true
    )
    
    (map-set access-permissions
      { participant: sender, accessor: accessor, resource-type: resource-type }
      { 
        granted: true, 
        expiry: expiry, 
        grant-time: block-height,
        fee-paid: fee-amount 
      }
    )
    
    (ok true)
  )
)

(define-public (revoke-access (accessor principal) (resource-type (string-ascii 64)))
  (let ((sender tx-sender))
    (asserts! (is-participant-registered sender) (err err-participant-does-not-exist))
    (asserts! (is-valid-resource-type resource-type) (err err-invalid-resource-type))
    
    (map-set access-permissions
      { participant: sender, accessor: accessor, resource-type: resource-type }
      { 
        granted: false, 
        expiry: none, 
        grant-time: block-height,
        fee-paid: u0 
      }
    )
    
    (ok true)
  )
)