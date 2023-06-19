# Embeddable WireGuard Library .NET Wrapper

A .NET wrapper for [embeddable-wg-library](https://git.zx2c4.com/wireguard-tools/tree/contrib/embeddable-wg-library).

## Usage

Install the package from nuget.org: `Install-Package Poteko.EmbeddableWireGuard.Net`, and follow the same usage as in the [C library](https://git.zx2c4.com/wireguard-tools/tree/contrib/embeddable-wg-library/test.c).

```c#
using EmbeddableWireGuard.Net;
WireGuardFunctions.AddDevice("wgtest");
var wgdev = new WireGuardDevice
{
    Name = "wgtest",
    Flags = WireGuardDeviceFlags.HasPrivateKey | WireGuardDeviceFlags.HasListenPort | WireGuardDeviceFlags.ReplacePeers,
    ListenPort = 34567,
    PrivateKey = Convert.FromBase64String("AABUdvCEVcxqQV4AyUdSOPjXlfptBV2T4j+RmbSoIEg="),
    Peers = new List<WireGuardPeer>{
        new WireGuardPeer {
            Flags = WireGuardPeerFlags.HasPublicKey | WireGuardPeerFlags.HasPersistentKeepaliveInterval | WireGuardPeerFlags.ReplaceAllowedIps,
            EndpointAddress = System.Net.IPAddress.Parse("fd58:b34c:c416::"),
            EndpointPort = 24455,
            PublicKey = Convert.FromBase64String("CCBUdvCEVcxqQV4AyUdSOPjXlfptBV2T4j+RmbSoIEg="),
            PersistentKeepaliveInterval = 30,
            AllowedIps = new List<WireGuardAllowedIp> {
                new WireGuardAllowedIp {
                    Address = IPAddress.Parse("2.3.4.5"),
                    Cidr = 32,
                },
                new WireGuardAllowedIp {
                    Address = IPAddress.Parse("ffee:ccdd:eecc:dead:beef::"),
                    Cidr = 64,
                }
            }
         },
    },
};
WireGuardFunctions.SetWireGuardDevice(wgdev);
var devices = WireGuardFunctions.ListDeviceNames().Select(name => GetWireGuardDevice(name)).ToList();
WireGuardFunctions.DeleteDevice("wgtest");
```

## License

The dependency *Embeddable WireGuard C Library* is [licensed under LGPL-2.1+](https://git.zx2c4.com/wireguard-tools/tree/contrib/embeddable-wg-library/README), while this wrapper is licensed under MIT.
