;; pulselink-core
;; 
;; This contract serves as the central component of the PulseLink Health Data Hub, 
;; handling user registration, data authorization permissions, and access control.
;; It maintains a registry of user accounts and their associated health data identifiers,
;; without storing the actual health data on-chain.
;;
;; The contract enables users to control who can access their health data and
;; maintains an auditable history of all access events.

;; Error codes
(define-constant err-unauthorized u1)
(define-constant err-user-already-exists u2)
(define-constant err-user-does-not-exist u3)
(define-constant err-device-already-registered u4)
(define-constant err-device-not-registered u5)
(define-constant err-consumer-not-verified u6)
(define-constant err-consumer-already-verified u7)
(define-constant err-access-not-granted u8)
(define-constant err-invalid-data-type u9)
(define-constant err-invalid-expiry u10)

;; Data types for health information categories
(define-constant data-type-heart-rate "heart-rate")
(define-constant data-type-blood-pressure "blood-pressure")
(define-constant data-type-sleep "sleep")
(define-constant data-type-activity "activity")
(define-constant data-type-glucose "glucose")
(define-constant data-type-oxygen "oxygen")
(define-constant data-type-temperature "temperature")
(define-constant data-type-weight "weight")

;; Data maps

;; Stores registered users 
(define-map users 
  { user: principal } 
  { registered: bool, registration-time: uint }
)

;; Maps users to their registered devices
(define-map user-devices 
  { user: principal, device-id: (string-ascii 64) } 
  { registered: bool, device-type: (string-ascii 64), registration-time: uint }
)

;; Stores verified data consumers (healthcare providers, research institutions, etc.)
(define-map verified-consumers
  { consumer: principal }
  { verified: bool, consumer-type: (string-ascii 64), verification-time: uint }
)

;; Maps data access permissions granted by users to consumers
(define-map data-access-permissions
  { user: principal, consumer: principal, data-type: (string-ascii 64) }
  { granted: bool, expiry: (optional uint), grant-time: uint }
)

;; Tracks access history for audit purposes
(define-map access-history
  { access-id: uint }
  { 
    user: principal, 
    consumer: principal, 
    data-type: (string-ascii 64), 
    access-time: uint,
    purpose: (string-ascii 128)
  }
)

;; Counter for access history entries
(define-data-var access-history-counter uint u0)

;; Private functions

;; Validates if a data type is supported
(define-private (is-valid-data-type (data-type (string-ascii 64)))
  (or
    (is-eq data-type data-type-heart-rate)
    (is-eq data-type data-type-blood-pressure)
    (is-eq data-type data-type-sleep)
    (is-eq data-type data-type-activity)
    (is-eq data-type data-type-glucose)
    (is-eq data-type data-type-oxygen)
    (is-eq data-type data-type-temperature)
    (is-eq data-type data-type-weight)
  )
)

;; Checks if user exists
(define-private (is-user-registered (user principal))
  (default-to false (get registered (map-get? users { user: user })))
)

;; Checks if device is registered to user
(define-private (is-device-registered (user principal) (device-id (string-ascii 64)))
  (default-to false (get registered (map-get? user-devices { user: user, device-id: device-id })))
)

;; Checks if consumer is verified
(define-private (is-consumer-verified (consumer principal))
  (default-to false (get verified (map-get? verified-consumers { consumer: consumer })))
)

;; Checks if user has granted access to consumer for specific data type
(define-private (has-access (user principal) (consumer principal) (data-type (string-ascii 64)))
  (let ((permission (map-get? data-access-permissions { user: user, consumer: consumer, data-type: data-type })))
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

;; Increments and returns the next access history ID
(define-private (next-access-id)
  (let ((current (var-get access-history-counter)))
    (var-set access-history-counter (+ current u1))
    current
  )
)

;; Record a data access event
(define-private (record-access (user principal) (consumer principal) (data-type (string-ascii 64)) (purpose (string-ascii 128)))
  (let ((access-id (next-access-id)))
    (map-set access-history
      { access-id: access-id }
      {
        user: user,
        consumer: consumer,
        data-type: data-type,
        access-time: block-height,
        purpose: purpose
      }
    )
    (ok access-id)
  )
)

;; Read-only functions

;; Check if a user is registered
(define-read-only (check-user-registration (user principal))
  (ok (is-user-registered user))
)

;; Check if a consumer is verified
(define-read-only (check-consumer-verification (consumer principal))
  (ok (is-consumer-verified consumer))
)

;; Check if consumer has access to user's data
(define-read-only (check-data-access (user principal) (consumer principal) (data-type (string-ascii 64)))
  (ok (has-access user consumer data-type))
)

;; Get access details for audit
(define-read-only (get-access-details (access-id uint))
  (ok (map-get? access-history { access-id: access-id }))
)

;; Get access history for a user
(define-read-only (get-user-access-history (user principal))
  ;; In a real implementation, this would use an indexer or return filtered results
  ;; Simplification for clarity: returns most recent access ID
  (ok (var-get access-history-counter))
)

;; Public functions

;; Register as a user in the PulseLink system
(define-public (register-user)
  (let ((sender tx-sender))
    (asserts! (not (is-user-registered sender)) (err err-user-already-exists))
    
    (map-set users
      { user: sender }
      { registered: true, registration-time: block-height }
    )
    
    (ok true)
  )
)

;; Register a device for a user
(define-public (register-device (device-id (string-ascii 64)) (device-type (string-ascii 64)))
  (let ((sender tx-sender))
    (asserts! (is-user-registered sender) (err err-user-does-not-exist))
    (asserts! (not (is-device-registered sender device-id)) (err err-device-already-registered))
    
    (map-set user-devices
      { user: sender, device-id: device-id }
      { registered: true, device-type: device-type, registration-time: block-height }
    )
    
    (ok true)
  )
)

;; Remove a device for a user
(define-public (remove-device (device-id (string-ascii 64)))
  (let ((sender tx-sender))
    (asserts! (is-user-registered sender) (err err-user-does-not-exist))
    (asserts! (is-device-registered sender device-id) (err err-device-not-registered))
    
    (map-set user-devices
      { user: sender, device-id: device-id }
      { registered: false, device-type: "", registration-time: u0 }
    )
    
    (ok true)
  )
)

;; Register as a verified data consumer (this would typically involve an off-chain verification process)
(define-public (register-consumer (consumer principal) (consumer-type (string-ascii 64)))
  (let ((sender tx-sender))
    ;; In a production environment, this would require administrative privileges
    ;; This is a simplification for the purpose of this implementation
    (asserts! (is-eq sender (as-contract tx-sender)) (err err-unauthorized))
    (asserts! (not (is-consumer-verified consumer)) (err err-consumer-already-verified))
    
    (map-set verified-consumers
      { consumer: consumer }
      { verified: true, consumer-type: consumer-type, verification-time: block-height }
    )
    
    (ok true)
  )
)

;; Grant data access to a verified consumer
(define-public (grant-data-access 
  (consumer principal) 
  (data-type (string-ascii 64)) 
  (expiry (optional uint)))
  (let ((sender tx-sender))
    (asserts! (is-user-registered sender) (err err-user-does-not-exist))
    (asserts! (is-consumer-verified consumer) (err err-consumer-not-verified))
    (asserts! (is-valid-data-type data-type) (err err-invalid-data-type))
    
    ;; If expiry is provided, ensure it's in the future
    (match expiry
      expiry-time (asserts! (> expiry-time block-height) (err err-invalid-expiry))
      true
    )
    
    (map-set data-access-permissions
      { user: sender, consumer: consumer, data-type: data-type }
      { granted: true, expiry: expiry, grant-time: block-height }
    )
    
    (ok true)
  )
)

;; Revoke data access from a consumer
(define-public (revoke-data-access (consumer principal) (data-type (string-ascii 64)))
  (let ((sender tx-sender))
    (asserts! (is-user-registered sender) (err err-user-does-not-exist))
    (asserts! (is-valid-data-type data-type) (err err-invalid-data-type))
    
    (map-set data-access-permissions
      { user: sender, consumer: consumer, data-type: data-type }
      { granted: false, expiry: none, grant-time: block-height }
    )
    
    (ok true)
  )
)