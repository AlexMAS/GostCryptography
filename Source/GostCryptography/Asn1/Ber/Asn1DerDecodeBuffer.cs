using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1DerDecodeBuffer : Asn1BerDecodeBuffer
	{
		public Asn1DerDecodeBuffer(byte[] msgdata)
			: base(msgdata)
		{
		}

		public Asn1DerDecodeBuffer(Stream inputStream)
			: base(inputStream)
		{
		}
	}
}