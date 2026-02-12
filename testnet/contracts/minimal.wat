(module
  ;; Absolute minimal contract - just pure math, no memory at all

  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )

  (func (export "mul") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.mul
  )
)
