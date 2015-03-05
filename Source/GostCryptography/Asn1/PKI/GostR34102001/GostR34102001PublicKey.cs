using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.PKI.GostR34102001
{
	class GostR34102001PublicKey : Asn1OctetString
	{
		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			base.Decode(buffer, explicitTagging, implicitLength);

			if (Length != 0x40)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "Length", Length);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (Length != 0x40)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "Length", Length);
			}

			var len = base.Encode(buffer, false);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}
	}
}