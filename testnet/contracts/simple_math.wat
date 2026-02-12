(module
  ;; Simple math functions for testing contract execution

  ;; Add two numbers
  (func (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add
  )

  ;; Multiply two numbers
  (func (export "multiply") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.mul
  )

  ;; Subtract two numbers
  (func (export "subtract") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.sub
  )

  ;; Divide two numbers (returns 0 if b is 0)
  (func (export "divide") (param $a i32) (param $b i32) (result i32)
    (if (result i32) (i32.eqz (local.get $b))
      (then (i32.const 0))
      (else
        (i32.div_u (local.get $a) (local.get $b))
      )
    )
  )

  ;; Calculate factorial (iterative)
  (func (export "factorial") (param $n i32) (result i32)
    (local $result i32)
    (local $i i32)

    (local.set $result (i32.const 1))
    (local.set $i (i32.const 2))

    (block $break
      (loop $continue
        (br_if $break (i32.gt_u (local.get $i) (local.get $n)))

        (local.set $result
          (i32.mul (local.get $result) (local.get $i))
        )

        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )

    (local.get $result)
  )

  ;; Check if number is even
  (func (export "is_even") (param $n i32) (result i32)
    (i32.eqz (i32.rem_u (local.get $n) (i32.const 2)))
  )

  ;; Calculate power (a^b)
  (func (export "power") (param $a i32) (param $b i32) (result i32)
    (local $result i32)
    (local $i i32)

    (local.set $result (i32.const 1))
    (local.set $i (i32.const 0))

    (block $break
      (loop $continue
        (br_if $break (i32.ge_u (local.get $i) (local.get $b)))

        (local.set $result (i32.mul (local.get $result) (local.get $a)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))

        (br $continue)
      )
    )

    (local.get $result)
  )

  ;; Test gas metering - compute intensive function
  (func (export "compute_heavy") (param $iterations i32) (result i32)
    (local $sum i32)
    (local $i i32)

    (local.set $sum (i32.const 0))
    (local.set $i (i32.const 0))

    (block $break
      (loop $continue
        (br_if $break (i32.ge_u (local.get $i) (local.get $iterations)))

        ;; Some computations
        (local.set $sum
          (i32.add
            (local.get $sum)
            (i32.mul (local.get $i) (i32.const 3))
          )
        )

        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )

    (local.get $sum)
  )
)
