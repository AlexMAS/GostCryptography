using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Encryption.Gost2814789
{
	class Gost2814789Mac : Asn1OctetString
	{
		public Gost2814789Mac()
		{
		}

		public Gost2814789Mac(byte[] data)
			: base(data)
		{
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			base.Decode(buffer, explicitTagging, implicitLength);

			if ((Length < 1) || (Length > 4))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "Length", Length);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if ((Length < 1) || (Length > 4))
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