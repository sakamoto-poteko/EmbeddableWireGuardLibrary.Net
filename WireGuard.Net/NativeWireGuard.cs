using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace WireGuard.Net
{
    internal static class Constants
    {
        internal const int IPADDR4_SIZE = 4;
        internal const int IPADDR6_SIZE = 16;
        internal const int IPADDR_MAXSIZE = IPADDR6_SIZE;
        internal const int SOCKADDR_SIZE = 16;
        internal const int SOCKADDR6_SIZE = 28;
        internal const int SOCKADDR_MAXSIZE = SOCKADDR6_SIZE;
        internal const int KEY_SIZE = 32;
        internal const int B64_KEY_SIZE = ((KEY_SIZE + 2) / 3) * 4 + 1;
        internal const int AF_INET = 2;
        internal const int AF_INET6 = 10;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct Timespec64
    {
        internal long TvSec;

        internal long TvNSec;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Size = Constants.SOCKADDR_SIZE)]
    internal class SockAddrInternet4
    {
        internal ushort Family;

        internal ushort Port;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        internal byte[] Address;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Size = Constants.SOCKADDR6_SIZE)]
    internal class SockAddrInternet6
    {
        internal ushort Family;

        internal ushort Port;

        internal uint FlowInfo;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] Address;

        internal uint ScopeId;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal class SockAddr
    {
        internal ushort Family;
    }

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi, Size = Constants.IPADDR_MAXSIZE)]
    internal struct InternetAddr
    {
        [FieldOffset(0)]
        internal uint Address4;

        [FieldOffset(0)]
        internal ulong Address6_0;

        [FieldOffset(8)]
        internal ulong Address6_1;

        internal IPAddress ToIP4Address()
        {
            return new IPAddress(Address4);
        }

        internal unsafe IPAddress ToIP6Address()
        {
            byte* addr = stackalloc byte[Constants.IPADDR6_SIZE];
            *(ulong*)addr = Address6_0;
            *(ulong*)(addr + 8) = Address6_1;
            return new IPAddress(new Span<byte>(addr, Constants.IPADDR6_SIZE));
        }

        internal unsafe void SetFromIPAddress(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            fixed (byte* ptr = bytes)
            {
                if (bytes.Length == Constants.IPADDR4_SIZE)
                {
                    Address4 = *(uint*)ptr;
                }
                else
                {
                    Address6_0 = *(ulong*)ptr;
                    Address6_1 = *(ulong*)(ptr + 8);
                }
            }
        }

        internal static InternetAddr FromIPAddress(IPAddress address)
        {
            var addr = new InternetAddr();
            addr.SetFromIPAddress(address);
            return addr;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 4)]
    internal class NativeWireGuardAllowedIp
    {
        internal NativeWireGuardAllowedIp()
        {
        }

        internal NativeWireGuardAllowedIp(WireGuardAllowedIp allowedIp)
        {
            var addressBytes = allowedIp.Address.GetAddressBytes();
            Array.Resize(ref addressBytes, Constants.IPADDR_MAXSIZE);
            this.Family = allowedIp.Address.AddressFamily switch
            {
                System.Net.Sockets.AddressFamily.InterNetwork => Constants.AF_INET,
                System.Net.Sockets.AddressFamily.InterNetworkV6 => Constants.AF_INET6,
                _ => throw new ArgumentOutOfRangeException("Address.AddressFamily", allowedIp.Address.AddressFamily, "unknown AddressFamily for Address in AllowedIp"),
            };
            this.Address = InternetAddr.FromIPAddress(allowedIp.Address);
            this.Cidr = allowedIp.Cidr;
        }

        internal ushort Family;

        internal InternetAddr Address;

        internal byte Cidr;

        internal IntPtr NextAllowedIp;

        internal IntPtr MarshalAsAllocatedPtr()
        {
            IntPtr ptr = IntPtr.Zero;
            ptr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeWireGuardAllowedIp>());
            Marshal.StructureToPtr(this, ptr, false);
            return ptr;
        }

        internal static void FreeAllocatedPtrLinkedList(IntPtr ptr)
        {
            while (ptr != IntPtr.Zero)
            {
                var current = ptr;
                var allowedIp = Marshal.PtrToStructure<NativeWireGuardAllowedIp>(ptr);
                ptr = allowedIp.NextAllowedIp;
                Marshal.FreeHGlobal(current);
            }
        }
    };


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal class NativeWireGuardPeer
    {
        internal NativeWireGuardPeer()
        {
        }

        internal NativeWireGuardPeer(WireGuardPeer peer)
        {
            this.Flags = peer.Flags;
            this.PublicKey = (byte[])peer.PublicKey?.Clone() ?? new byte[Constants.KEY_SIZE];
            this.PresharedKey = (byte[])peer.PresharedKey?.Clone() ?? new byte[Constants.KEY_SIZE];
            this.LastHandshakeTime = new Timespec64 { TvSec = (long)peer.LastHandshakeTime.TotalSeconds };
            this.RxBytes = peer.RxBytes;
            this.TxBytes = peer.TxBytes;
            this.PersistentKeepaliveInterval = peer.PersistentKeepaliveInterval;
            this.FirstAllowedIp = IntPtr.Zero;
            this.LastAllowedIp = IntPtr.Zero;


            IntPtr sockaddr_ptr = IntPtr.Zero;
            if (peer.EndpointAddress != null)
            {
                try
                {
                    sockaddr_ptr = Marshal.AllocHGlobal(Constants.SOCKADDR_MAXSIZE);
                    this.Endpoint = new byte[Constants.SOCKADDR_MAXSIZE];
                    switch (peer.EndpointAddress.AddressFamily)
                    {
                        case System.Net.Sockets.AddressFamily.InterNetwork:
                            var sockaddr_in = new SockAddrInternet4
                            {
                                Family = Constants.AF_INET,
                                Port = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(peer.EndpointPort) : peer.EndpointPort,
                                Address = peer.EndpointAddress.GetAddressBytes(),
                            };
                            Marshal.StructureToPtr(sockaddr_in, sockaddr_ptr, true);
                            Marshal.Copy(sockaddr_ptr, this.Endpoint, 0, Constants.SOCKADDR_SIZE);
                            break;
                        case System.Net.Sockets.AddressFamily.InterNetworkV6:
                            var sockaddr_in6 = new SockAddrInternet6
                            {
                                Family = Constants.AF_INET6,
                                Port = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(peer.EndpointPort) : peer.EndpointPort,
                                Address = peer.EndpointAddress.GetAddressBytes(),
                            };
                            Marshal.StructureToPtr(sockaddr_in6, sockaddr_ptr, true);
                            Marshal.Copy(sockaddr_ptr, this.Endpoint, 0, Constants.SOCKADDR6_SIZE);
                            break;
                        default:
                            throw new ArgumentOutOfRangeException("EndpointAddress.AddressFamily", peer.EndpointAddress.AddressFamily, "unknown AddressFamily for EndpointAddress");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(sockaddr_ptr);
                }
            }

            if (peer.AllowedIps.Count > 0)
            {
                List<NativeWireGuardAllowedIp> allowedIps = peer.AllowedIps.Select(allowedIp => new NativeWireGuardAllowedIp(allowedIp)).ToList();
                List<IntPtr> allowedIpPtrs = new List<IntPtr>();
                IntPtr last = IntPtr.Zero;

                // NativeWireGuardPeer is a linked list
                for (int i = allowedIps.Count - 1; i >= 0; i--)
                {
                    allowedIps[i].NextAllowedIp = last;
                    IntPtr ptr = allowedIps[i].MarshalAsAllocatedPtr();
                    allowedIpPtrs.Add(ptr);
                    last = ptr;
                }

                this.FirstAllowedIp = allowedIpPtrs.Last();
                this.LastAllowedIp = allowedIpPtrs.First();
            }
        }

        internal WireGuardPeerFlags Flags;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.KEY_SIZE)]
        internal byte[] PublicKey;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.KEY_SIZE)]
        internal byte[] PresharedKey;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.SOCKADDR_MAXSIZE)]
        internal byte[] Endpoint;

        internal Timespec64 LastHandshakeTime;

        internal ulong RxBytes;

        internal ulong TxBytes;

        internal ushort PersistentKeepaliveInterval;

        internal IntPtr FirstAllowedIp;

        internal IntPtr LastAllowedIp;

        internal IntPtr NextPeer;

        internal IntPtr MarshalAsAllocatedPtr()
        {
            IntPtr ptr = IntPtr.Zero;
            ptr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeWireGuardPeer>());
            Marshal.StructureToPtr(this, ptr, false);
            return ptr;
        }

        internal static void FreeAllocatedPtrLinkedList(IntPtr ptr)
        {
            while (ptr != IntPtr.Zero)
            {
                var current = ptr;
                var peer = Marshal.PtrToStructure<NativeWireGuardPeer>(ptr);
                ptr = peer.NextPeer;
                NativeWireGuardAllowedIp.FreeAllocatedPtrLinkedList(peer.FirstAllowedIp);
                Marshal.FreeHGlobal(current);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal class NativeWireGuardDevice
    {
        internal NativeWireGuardDevice()
        {

        }

        internal NativeWireGuardDevice(WireGuardDevice device)
        {

            this.Name = device.Name;
            this.Index = device.Index;
            this.Flags = device.Flags;
            this.PublicKey = (byte[])device.PublicKey?.Clone() ?? new byte[Constants.KEY_SIZE];
            this.PrivateKey = (byte[])device.PrivateKey?.Clone() ?? new byte[Constants.KEY_SIZE];
            this.FwMark = device.FwMark;
            this.ListenPort = device.ListenPort;
            this.FirstPeer = IntPtr.Zero;
            this.LastPeer = IntPtr.Zero;

            // peers
            if (device.Peers.Count > 0)
            {
                List<NativeWireGuardPeer> peers = device.Peers.Select(peer => new NativeWireGuardPeer(peer)).ToList();
                List<IntPtr> peerPtrs = new List<IntPtr>();
                IntPtr last = IntPtr.Zero;

                // NativeWireGuardPeer is a linked list
                for (int i = peers.Count - 1; i >= 0; i--)
                {
                    peers[i].NextPeer = last;
                    IntPtr ptr = peers[i].MarshalAsAllocatedPtr();
                    peerPtrs.Add(ptr);
                    last = ptr;
                }

                // reversed
                this.FirstPeer = peerPtrs.Last();
                this.LastPeer = peerPtrs.First();
            }
        }

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        internal string Name;

        internal uint Index;

        internal WireGuardDeviceFlags Flags;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.KEY_SIZE)]
        internal byte[] PublicKey;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.KEY_SIZE)]
        internal byte[] PrivateKey;

        internal uint FwMark;

        internal ushort ListenPort;

        internal IntPtr FirstPeer;

        internal IntPtr LastPeer;
    }


    internal static class NativeWireGuardFunctions
    {
        [DllImport("libc", SetLastError = true)]
        internal static extern void free(IntPtr ptr);

        [DllImport("libc", SetLastError = true)]
        internal static extern IntPtr strerror(int errnum);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern IntPtr wg_list_device_names();

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern int wg_add_device([MarshalAs(UnmanagedType.LPStr)] string deviceName);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern int wg_del_device([MarshalAs(UnmanagedType.LPStr)] string deviceName);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern int wg_set_device(NativeWireGuardDevice dev);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern int wg_get_device(out IntPtr device, [MarshalAs(UnmanagedType.LPStr)] string deviceName);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern void wg_free_device(IntPtr dev);


        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern void wg_key_to_base64([MarshalAs(UnmanagedType.LPArray)] byte[] base64, [MarshalAs(UnmanagedType.LPArray)] byte[] key);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern int wg_key_from_base64([MarshalAs(UnmanagedType.LPArray)] byte[] key, [MarshalAs(UnmanagedType.LPStr)] string base64);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern bool wg_key_is_zero([MarshalAs(UnmanagedType.LPArray)] byte[] key);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern void wg_generate_public_key([MarshalAs(UnmanagedType.LPArray)] byte[] public_key, [MarshalAs(UnmanagedType.LPArray)] byte[] private_key);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern void wg_generate_private_key([MarshalAs(UnmanagedType.LPArray)] byte[] private_key);

        [DllImport("wireguard.so", CharSet = CharSet.Ansi)]
        internal static extern void wg_generate_preshared_key([MarshalAs(UnmanagedType.LPArray)] byte[] preshared_key);
    }
}