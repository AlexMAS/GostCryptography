using System.IO;

namespace GostCryptography.Asn1.Ber
{
	class Asn1CerInputStream : Asn1BerInputStream
	{
		public Asn1CerInputStream(Stream inputStream)
			: base(inputStream)
		{
		}
	}
}