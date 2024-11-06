(module
    (import "runtime" "getCurrentLabel" (func $getCurrentLabel (result externref)))
    (import "runtime" "buckleParse" (func $buckleParse (param i32) (param i32) (result externref)))
    (import "runtime" "printExternRef" (func $printExternRef (param externref)))
    (import "runtime" "taintWithLabel" (func $taintWithLabel (param externref) (result externref)))
    (memory (export "memory") 2 3)
    (data (i32.const 0x1000) "Dwaha,Dwaha")

    (func (export "run")
        i32.const 0x1000
        i32.const 11
        call $buckleParse
        call $taintWithLabel
        drop
        call $getCurrentLabel
        call $printExternRef
    )
)