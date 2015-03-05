using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Encryption.Gost2814789
{
	class Gost2814789EncryptedKey : Asn1Type
	{
		public Gost2814789Key EncryptedKey;
		public Gost2814789Mac MacKey;

		private Gost2814789Key _maskKey;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptedKey = new Gost2814789Key();
			EncryptedKey.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0x80, 0, EocTypeCode, parsedLen, true))
			{
				_maskKey = new Gost2814789Key();
				_maskKey.Decode(buffer, false, parsedLen.Value);
			}

			if (!context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			MacKey = new Gost2814789Mac();
			MacKey.Decode(buffer, true, parsedLen.Value);

			if (MacKey.Length != 4)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "MacKey.Length", MacKey.Length);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (MacKey.Length != 4)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, "MacKey.Length", MacKey.Length);
			}

			var num2 = MacKey.Encode(buffer, true);
			len += num2;

			if (_maskKey != null)
			{
				num2 = _maskKey.Encode(buffer, false);
				len += num2;
				len += buffer.EncodeTagAndLength(0x80, 0, EocTypeCode, num2);
			}

			num2 = EncryptedKey.Encode(buffer, true);
			len += num2;

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			EncryptedKey = null;
			MacKey = null;

			_maskKey = null;
		}
	}
}