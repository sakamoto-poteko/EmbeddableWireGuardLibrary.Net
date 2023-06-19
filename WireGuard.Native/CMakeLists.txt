cmake_minimum_required (VERSION 3.10)

project(wireguard)

add_library(wireguard SHARED
"wireguard-tools/contrib/embeddable-wg-library/wireguard.c"
"wireguard-tools/contrib/embeddable-wg-library/wireguard.h"
)

