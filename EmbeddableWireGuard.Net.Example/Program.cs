using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using EmbeddableWireGuard.Net;


var names = WireGuardFunctions.ListDeviceNames();
var opt = new JsonSerializerOptions
{
    WriteIndented = true
};
opt.Converters.Add(new WireGuardAllowedIpJsonConverter());
opt.Converters.Add(new IPAddressJsonConverter());
opt.Converters.Add(new JsonStringEnumConverter());

foreach (var wg in names)
{
    var dev = WireGuardFunctions.GetWireGuardDevice(wg);
    Console.WriteLine(JsonSerializer.Serialize(dev, opt));
}

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
            PersistentKeepaliveInterval = 23,
            AllowedIps = new List<WireGuardAllowedIp> {
                new WireGuardAllowedIp {
                    Address = IPAddress.Parse("2.3.4.5"),
                    Cidr = 32,
                },
                new WireGuardAllowedIp {
                    Address = IPAddress.Parse("ffee:ccdd:eecc:dead:beef::"),
                    Cidr = 72,
                }
            }
         },
        new WireGuardPeer {
            Flags = WireGuardPeerFlags.HasPublicKey | WireGuardPeerFlags.HasPersistentKeepaliveInterval | WireGuardPeerFlags.ReplaceAllowedIps,
            EndpointAddress = System.Net.IPAddress.Parse("1.2.3.4"),
            EndpointPort = 33221,
            PublicKey = Convert.FromBase64String("BBCCDDEEFFxqQV4AyUdSOPjXlfptBV2T4j+RmbSoIEg="),
            PersistentKeepaliveInterval = 58,
            AllowedIps = new List<WireGuardAllowedIp> {
                new WireGuardAllowedIp {
                    Address = IPAddress.Parse("fd33:9876:5432:1098::"),
                    Cidr = 64,
                },
                new WireGuardAllowedIp {
                    Address = IPAddress.Parse("7.8.9.10"),
                    Cidr = 24,
                }
            }
         }
    },
};
WireGuardFunctions.SetWireGuardDevice(wgdev);

var readback = WireGuardFunctions.GetWireGuardDevice("wgtest");
Console.WriteLine(JsonSerializer.Serialize(readback, opt));


var psk = WireGuardFunctions.GeneratePresharedKey();
var privKey = WireGuardFunctions.GeneratePrivateKey();
var pubKey = WireGuardFunctions.GeneratePublicKey(privKey);

var privB64 = WireGuardFunctions.ConvertKeyToBase64(privKey);
var pubB64 = WireGuardFunctions.ConvertKeyToBase64(pubKey);
var pskB64 = WireGuardFunctions.ConvertKeyToBase64(psk);

var priv = WireGuardFunctions.ConvertBase64ToKey(privB64);
var pub = WireGuardFunctions.ConvertBase64ToKey(pubB64);

Console.WriteLine(privB64);
Console.WriteLine(pubB64);
Console.WriteLine(pskB64);

Console.WriteLine($"priv same: {Enumerable.SequenceEqual(privKey, priv)}, pub same: {Enumerable.SequenceEqual(pubKey, pub)}");

WireGuardFunctions.DeleteDevice("wgtest");