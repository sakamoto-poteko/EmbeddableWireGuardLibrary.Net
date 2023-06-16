namespace WireGuard.Net
{
    [System.Serializable]
    public class WireGuardException : System.Exception
    {
        public WireGuardException() { }
        internal WireGuardException(int errno) : base(WireGuardFunctions.GetErrorMessage(errno)) {}
        public WireGuardException(string message) : base(message) { }
        public WireGuardException(string message, System.Exception inner) : base(message, inner) { }
        protected WireGuardException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}