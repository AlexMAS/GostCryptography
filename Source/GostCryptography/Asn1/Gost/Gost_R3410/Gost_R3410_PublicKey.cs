using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	public abstract class Gost_R3410_PublicKey : Asn1OctetString
	{
		private readonly int _keySize;

		protected Gost_R3410_PublicKey(int keySize)
		{
			_keySize = keySize;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			base.Decode(buffer, explicitTagging, implicitLength);

			if (Length != _keySize)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(Length), Length);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (Length != _keySize)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(Length), Length);
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