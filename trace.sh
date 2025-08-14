TR=/sys/kernel/tracing; [ -d /sys/kernel/debug/tracing ] && TR=/sys/kernel/debug/tracing
sudo mkdir -p $TR/instances/xdp
IR=$TR/instances/xdp

echo 0 > $IR/tracing_on
find $IR/events -name enable -exec sh -c 'echo 0 > "$1"' _ {} \; 2>/dev/null

# Enable only what you want in the instance
[ -f $IR/events/bpf/bpf_trace_printk/enable ] && echo 1 > $IR/events/bpf/bpf_trace_printk/enable
# or: echo 1 > $IR/events/xdp/xdp_exception/enable

echo 1 > $IR/tracing_on
cat $IR/trace_pipe
