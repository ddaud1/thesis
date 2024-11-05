(module
    (import "runtime" "getCurrentLabel" (func $getCurrentLabel (result externref)))
    (import "runtime" "printExternRef" (func $printExternRef (param externref)))
    (memory (export "memory") 2 3)
    (data (i32.const 0x1000) "hello hello h")

    (func (export "run")
        call $getCurrentLabel
        call $printExternRef
    )
)