namespace GostCryptography.Asn1.Ber
{
	public class Asn1DerEncodeBuffer : Asn1BerEncodeBuffer
	{
		public Asn1DerEncodeBuffer()
		{
			ByteIndex = SizeIncrement - 1;
		}

		public Asn1DerEncodeBuffer(int sizeIncrement)
			: base(sizeIncrement)
		{
			ByteIndex = SizeIncrement - 1;
		}
	}
}