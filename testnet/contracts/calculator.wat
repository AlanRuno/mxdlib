(module
  ;; Pure computation contract - no memory, no growth, fully deterministic

  ;; Add two numbers
  (func (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add
  )

  ;; Multiply two numbers
  (func (export "mul") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.mul
  )

  ;; Subtract two numbers
  (func (export "sub") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.sub
  )

  ;; Divide two numbers (returns 0 if b is 0 to avoid trap)
  (func (export "div") (param $a i32) (param $b i32) (result i32)
    (if (result i32) (i32.eqz (local.get $b))
      (then (i32.const 0))
      (else
        (i32.div_u (local.get $a) (local.get $b))
      )
    )
  )

  ;; Modulo operation
  (func (export "mod") (param $a i32) (param $b i32) (result i32)
    (if (result i32) (i32.eqz (local.get $b))
      (then (i32.const 0))
      (else
        (i32.rem_u (local.get $a) (local.get $b))
      )
    )
  )

  ;; Power function (a^b)
  (func (export "pow") (param $a i32) (param $b i32) (result i32)
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

  ;; Factorial (iterative)
  (func (export "fac") (param $n i32) (result i32)
    (local $result i32)
    (local $i i32)

    (local.set $result (i32.const 1))
    (local.set $i (i32.const 2))

    (block $break
      (loop $continue
        (br_if $break (i32.gt_u (local.get $i) (local.get $n)))
        (local.set $result (i32.mul (local.get $result) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )

    (local.get $result)
  )

  ;; Test if even
  (func (export "even") (param $n i32) (result i32)
    (i32.eqz (i32.rem_u (local.get $n) (i32.const 2)))
  )

  ;; Greatest common divisor (GCD)
  (func (export "gcd") (param $a i32) (param $b i32) (result i32)
    (local $temp i32)

    (block $break
      (loop $continue
        (br_if $break (i32.eqz (local.get $b)))

        (local.set $temp (i32.rem_u (local.get $a) (local.get $b)))
        (local.set $a (local.get $b))
        (local.set $b (local.get $temp))

        (br $continue)
      )
    )

    (local.get $a)
  )

  ;; Fibonacci (iterative)
  (func (export "fib") (param $n i32) (result i32)
    (local $a i32)
    (local $b i32)
    (local $temp i32)
    (local $i i32)

    (if (result i32) (i32.le_u (local.get $n) (i32.const 1))
      (then (local.get $n))
      (else
        (local.set $a (i32.const 0))
        (local.set $b (i32.const 1))
        (local.set $i (i32.const 2))

        (block $break
          (loop $continue
            (br_if $break (i32.gt_u (local.get $i) (local.get $n)))

            (local.set $temp (i32.add (local.get $a) (local.get $b)))
            (local.set $a (local.get $b))
            (local.set $b (local.get $temp))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))

            (br $continue)
          )
        )

        (local.get $b)
      )
    )
  )
)
