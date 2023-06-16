using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using WireGuard.Net;

public class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
            throw new NotSupportedException();

    public override void Write(
        Utf8JsonWriter writer,
        IPAddress ipAddress,
        JsonSerializerOptions options) =>
            writer.WriteStringValue(ipAddress.ToString());
}

public class WireGuardAllowedIpJsonConverter : JsonConverter<WireGuardAllowedIp>
{
    public override WireGuardAllowedIp Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
            throw new NotSupportedException();

    public override void Write(
        Utf8JsonWriter writer,
        WireGuardAllowedIp allowedIp,
        JsonSerializerOptions options) =>
            writer.WriteStringValue($"{allowedIp.Address}/{allowedIp.Cidr}");
}