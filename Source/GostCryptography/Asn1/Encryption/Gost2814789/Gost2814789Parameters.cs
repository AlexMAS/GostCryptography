using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Encryption.Gost2814789
{
	class Gost2814789Parameters : Asn1Type
	{
		private Gost2814789ParamSet _encryptionParamSet;
		private Gost2814789Iv _iv;

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

			_iv = new Gost2814789Iv();
			_iv.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			_encryptionParamSet = new Gost2814789ParamSet();
			_encryptionParamSet.Decode(buffer, true, parsedLen.Value);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			var num2 = _encryptionParamSet.Encode(buffer, true);
			len += num2;

			num2 = _iv.Encode(buffer, true);
			len += num2;

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			_iv = null;
			_encryptionParamSet = null;
		}
	}
}