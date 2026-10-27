;; WISP++ ABI v1 demo: JSON passthrough to gated host commands.
;; exec_json(args) -> host_exec(args) -> {"ok","output","exit"} of e.g. {"cmd":"sysinfo"}
(module
  (import "env" "host_exec" (func $host_exec (param i32 i32) (result i64)))
  (import "env" "host_log" (func $host_log (param i32 i32)))
  (memory (export "memory") 2)
  (global $hp (mut i32) (i32.const 4096))
  (func (export "alloc") (param $n i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (i32.add (local.get $n) (i32.const 16))))
    (local.get $p))
  (func (export "exec_json") (param $p i32) (param $l i32) (result i64)
    (call $host_log (local.get $p) (local.get $l))
    (call $host_exec (local.get $p) (local.get $l))))
