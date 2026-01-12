## ngtcp2 demo README

## Building envirnoment and compiling

`./cooking.sh -t Dev  -e numactl  -e colm  -e ragel  -e Protobuf  -e gmp  -e libpciaccess  -e nettle -e hwloc  -e yaml-cpp  -e libxml2  -e Boost -e dpdk`

`cd build`

`ninja ngtcp2_client_demo` / `ninja ngtcp2_server_demo`

In case of `ninja: error: loading 'build.ninja': No such file or directory` just type `ninja any_other_demo`

I had to remove dpdk submodule.


## Useful commands to kill remaining seastar processes and check if they are occupying your resources.
cat /proc/sys/fs/aio-max-nr

cat /proc/sys/fs/aio-nr

ps -ef | grep -E "demo|seastar|ngtcp2"