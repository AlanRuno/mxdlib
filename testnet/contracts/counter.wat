(module
  ;; Import host functions for contract storage
  (import "env" "storage_read" (func $storage_read (param i32 i32 i32 i32) (result i32)))
  (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32)))

  ;; Memory for storage operations
  (memory (export "memory") 1)

  ;; Storage key for counter (at offset 0)
  (data (i32.const 0) "counter")

  ;; Initialize counter to 0
  (func (export "init")
    ;; Write 0 to counter storage
    (i32.store (i32.const 100) (i32.const 0))  ;; value at offset 100
    (call $storage_write
      (i32.const 0)    ;; key offset ("counter")
      (i32.const 7)    ;; key length
      (i32.const 100)  ;; value offset
      (i32.const 4)    ;; value length (4 bytes for i32)
    )
  )

  ;; Increment counter
  (func (export "increment") (result i32)
    (local $current i32)

    ;; Read current value
    (call $storage_read
      (i32.const 0)    ;; key offset
      (i32.const 7)    ;; key length
      (i32.const 100)  ;; output offset
      (i32.const 4)    ;; output length
    )
    drop

    ;; Load current value
    (local.set $current (i32.load (i32.const 100)))

    ;; Increment
    (local.set $current (i32.add (local.get $current) (i32.const 1)))

    ;; Write back
    (i32.store (i32.const 100) (local.get $current))
    (call $storage_write
      (i32.const 0)    ;; key offset
      (i32.const 7)    ;; key length
      (i32.const 100)  ;; value offset
      (i32.const 4)    ;; value length
    )

    ;; Return new value
    (local.get $current)
  )

  ;; Decrement counter
  (func (export "decrement") (result i32)
    (local $current i32)

    ;; Read current value
    (call $storage_read
      (i32.const 0)
      (i32.const 7)
      (i32.const 100)
      (i32.const 4)
    )
    drop

    ;; Load and decrement
    (local.set $current (i32.load (i32.const 100)))
    (local.set $current (i32.sub (local.get $current) (i32.const 1)))

    ;; Write back
    (i32.store (i32.const 100) (local.get $current))
    (call $storage_write
      (i32.const 0)
      (i32.const 7)
      (i32.const 100)
      (i32.const 4)
    )

    ;; Return new value
    (local.get $current)
  )

  ;; Get current counter value
  (func (export "get") (result i32)
    ;; Read current value
    (call $storage_read
      (i32.const 0)
      (i32.const 7)
      (i32.const 100)
      (i32.const 4)
    )
    drop

    ;; Return value
    (i32.load (i32.const 100))
  )
)
