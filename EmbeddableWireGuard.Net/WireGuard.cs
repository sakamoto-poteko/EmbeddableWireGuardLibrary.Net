using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace EmbeddableWireGuard.Net
{
    [Flags]
    public enum WireGuardDeviceFlags
    {
        ReplacePeers = 1 << 0,
        HasPrivateKey = 1 << 1,
        HasPublicKey = 1 << 2,
        HasListenPort = 1 << 3,
        HasFwMark = 1 << 4,
    }

    [Flags]
    public enum WireGuardPeerFlags
    {
        RemoveMe = 1 << 0,
        ReplaceAllowedIps = 1 << 1,
        HasPublicKey = 1 << 2,
        HasPresharedKey = 1 << 3,
        HasPersistentKeepaliveInterval = 1 << 4,
    };

    public class WireGuardDevice
    {
        public WireGuardDevice()
        {
        }

        internal WireGuardDevice(NativeWireGuardDevice nativeWireGuardDevice)
        {
            Name = nativeWireGuardDevice.Name;
            Index = nativeWireGuardDevice.Index;
            Flags = nativeWireGuardDevice.Flags;
            PublicKey = (byte[])nativeWireGuardDevice.PublicKey.Clone();
            PrivateKey = (byte[])nativeWireGuardDevice.PrivateKey.Clone();
            FwMark = nativeWireGuardDevice.FwMark;
            ListenPort = nativeWireGuardDevice.ListenPort;

            IntPtr next = nativeWireGuardDevice.FirstPeer;
            while (next != IntPtr.Zero)
            {
                var nativePeer = Marshal.PtrToStructure<NativeWireGuardPeer>(next);
                var peer = new WireGuardPeer(nativePeer);
                Peers.Add(peer);
                next = nativePeer.NextPeer;
            }
        }

        public string Name { get; set; }

        public uint Index { get; set; }

        public WireGuardDeviceFlags Flags { get; set; }

        public byte[] PublicKey { get; set; }

        public byte[] PrivateKey { get; set; }

        public uint FwMark { get; set; }

        public ushort ListenPort { get; set; }

        public List<WireGuardPeer> Peers { get; set; } = new List<WireGuardPeer>();
    }

    public class WireGuardPeer
    {
        public WireGuardPeer()
        {
        }

        internal WireGuardPeer(NativeWireGuardPeer peer)
        {
            Flags = peer.Flags;
            PublicKey = (byte[])peer.PublicKey?.Clone();
            PresharedKey = (byte[])peer.PresharedKey?.Clone();
            // Endpoint Addr and Port
            LastHandshakeTime = TimeSpan.FromSeconds(peer.LastHandshakeTime.TvSec);
            RxBytes = peer.RxBytes;
            TxBytes = peer.TxBytes;
            PersistentKeepaliveInterval = peer.PersistentKeepaliveInterval;

            unsafe
            {
                fixed (byte* ptr = peer.Endpoint)
                {
                    var sockaddr = Marshal.PtrToStructure<SockAddr>((IntPtr)ptr);
                    ushort netEndianPort = 0;
                    switch (sockaddr.Family)
                    {
                        // AF_INET
                        case Constants.AF_INET:
                            var sockaddr_in = Marshal.PtrToStructure<SockAddrInternet4>((IntPtr)ptr);
                            EndpointAddress = new IPAddress(sockaddr_in.Address);
                            netEndianPort = sockaddr_in.Port;
                            break;
                        // AF_INET6
                        case Constants.AF_INET6:
                            var sockaddr_in6 = Marshal.PtrToStructure<SockAddrInternet6>((IntPtr)ptr);
                            EndpointAddress = new IPAddress(new Span<byte>(sockaddr_in6.Address, 0, 16));
                            netEndianPort = sockaddr_in6.Port;
                            break;
                        default:
                            throw new WireGuardException($"Unknown address family for endpoint IP: {sockaddr.Family}");
                    }
                    EndpointPort = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(netEndianPort) : netEndianPort;
                }
            }

            var next = peer.FirstAllowedIp;
            while (next != IntPtr.Zero)
            {
                var nativeAllowed = Marshal.PtrToStructure<NativeWireGuardAllowedIp>(next);
                var allowed = new WireGuardAllowedIp(nativeAllowed);
                AllowedIps.Add(allowed);
                next = nativeAllowed.NextAllowedIp;
            }
        }

        public WireGuardPeerFlags Flags { get; set; }

        public byte[] PublicKey { get; set; }

        public byte[] PresharedKey { get; set; }

        public IPAddress EndpointAddress { get; set; }

        public ushort EndpointPort { get; set; }

        public TimeSpan LastHandshakeTime { get; set; }

        public ulong RxBytes { get; set; }

        public ulong TxBytes { get; set; }

        public ushort PersistentKeepaliveInterval { get; set; }

        public List<WireGuardAllowedIp> AllowedIps { get; set; } = new List<WireGuardAllowedIp>();
    }

    public class WireGuardAllowedIp
    {
        public WireGuardAllowedIp()
        {
        }

        internal WireGuardAllowedIp(NativeWireGuardAllowedIp nativeAllowedIp)
        {
            Cidr = nativeAllowedIp.Cidr;
            switch (nativeAllowedIp.Family)
            {
                case Constants.AF_INET:
                    Address = nativeAllowedIp.Address.ToIP4Address();
                    break;

                case Constants.AF_INET6:
                    Address = nativeAllowedIp.Address.ToIP6Address();
                    break;

                default:
                    throw new WireGuardException($"Unknown address family for allowed IP: {nativeAllowedIp.Family}");
            }
        }

        public IPAddress Address { get; set; }

        public byte Cidr { get; set; }
    };

    public static class WireGuardFunctions
    {
        internal static string GetErrorMessage(int errnum)
        {
            var errStr = NativeWireGuardFunctions.strerror(errnum);
            return Marshal.PtrToStringUTF8(errStr);
        }

        public static List<String> ListDeviceNames()
        {
            IntPtr retStr = NativeWireGuardFunctions.wg_list_device_names();
            unsafe
            {
                byte* head = (byte*)retStr;
                byte* current = head;
                /* "first\0second\0third\0forth\0last\0\0" */
                while (!(*current == 0 && *(current + 1) == 0))
                {
                    current++;
                }

                var span = new Span<byte>(head, (int)(current - head));
                // str does not have '\0' termination nor '\0\0'
                var str = System.Text.Encoding.ASCII.GetString(span);

                NativeWireGuardFunctions.free(retStr);
                return str.Split('\0').ToList();
            }
        }

        public static WireGuardDevice GetWireGuardDevice(string name)
        {
            int rc = NativeWireGuardFunctions.wg_get_device(out var devPtr, name);
            if (rc < 0)
            {
                throw new WireGuardException(-rc);
            }

            var nativeDev = Marshal.PtrToStructure<NativeWireGuardDevice>(devPtr);
            var dev = new WireGuardDevice(nativeDev);
            NativeWireGuardFunctions.wg_free_device(devPtr);
            return dev;
        }

        public static void SetWireGuardDevice(WireGuardDevice device)
        {
            var native = new NativeWireGuardDevice(device);
            try
            {
                int rc = NativeWireGuardFunctions.wg_set_device(native);
                if (rc < 0)
                {
                    throw new WireGuardException(-rc);
                }
            }
            finally
            {
                NativeWireGuardPeer.FreeAllocatedPtrLinkedList(native.FirstPeer);
            }
        }

        public static void AddDevice(string deviceName)
        {
            int rc = NativeWireGuardFunctions.wg_add_device(deviceName);
            if (rc < 0)
            {
                throw new WireGuardException(-rc);
            }
        }

        public static void DeleteDevice(string deviceName)
        {
            int rc = NativeWireGuardFunctions.wg_del_device(deviceName);
            if (rc < 0)
            {
                throw new WireGuardException(-rc);
            }
        }


        public static string ConvertKeyToBase64(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length != Constants.KEY_SIZE)
            {
                throw new ArgumentOutOfRangeException(nameof(key), $"the key size must be {Constants.KEY_SIZE}");
            }

            var buffer = new byte[Constants.B64_KEY_SIZE];
            NativeWireGuardFunctions.wg_key_to_base64(buffer, key);
            return System.Text.Encoding.UTF8.GetString(buffer, 0, Constants.B64_KEY_SIZE - 1);
        }

        public static byte[] ConvertBase64ToKey(string base64)
        {
            if (base64 == null)
            {
                throw new ArgumentNullException(nameof(base64));
            }

            if (base64.Length != Constants.B64_KEY_SIZE && base64.Length != Constants.B64_KEY_SIZE - 1)
            {
                throw new ArgumentOutOfRangeException(nameof(base64), $"the base64 size must be {Constants.B64_KEY_SIZE}");
            }

            var buffer = new byte[Constants.KEY_SIZE];
            int rc = NativeWireGuardFunctions.wg_key_from_base64(buffer, base64);
            if (rc < 0)
            {
                throw new WireGuardException(-rc);
            }

            return buffer;
        }

        public static bool IsKeyZero([MarshalAs(UnmanagedType.LPArray)] byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length != Constants.KEY_SIZE)
            {
                throw new ArgumentOutOfRangeException(nameof(key), $"the key size must be {Constants.KEY_SIZE}");
            }

            return NativeWireGuardFunctions.wg_key_is_zero(key);
        }

        public static byte[] GeneratePublicKey(byte[] privateKey)
        {
            var buffer = new byte[Constants.KEY_SIZE];
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }

            if (privateKey.Length != Constants.KEY_SIZE)
            {
                throw new ArgumentOutOfRangeException(nameof(privateKey), $"the key size must be {Constants.KEY_SIZE}");
            }

            NativeWireGuardFunctions.wg_generate_public_key(buffer, privateKey);
            return buffer;
        }

        public static byte[] GeneratePrivateKey()
        {
            var buffer = new byte[Constants.KEY_SIZE];
            NativeWireGuardFunctions.wg_generate_private_key(buffer);
            return buffer;
        }

        public static byte[] GeneratePresharedKey()
        {
            var buffer = new byte[Constants.KEY_SIZE];
            NativeWireGuardFunctions.wg_generate_preshared_key(buffer);
            return buffer;
        }
    }

}
