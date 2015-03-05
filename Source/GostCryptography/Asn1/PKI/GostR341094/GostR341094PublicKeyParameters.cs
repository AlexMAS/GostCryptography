using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.PKI.GostR341094
{
	class GostR341094PublicKeyParameters : Asn1Type
	{
		private Asn1ObjectIdentifier _digestParamSet;
		private Gost2814789ParamSet _encryptionParamSet;
		private Asn1ObjectIdentifier _publicKeyParamSet;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, 6, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			_publicKeyParamSet = new Asn1ObjectIdentifier();
			_publicKeyParamSet.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0, 6, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			_digestParamSet = new Asn1ObjectIdentifier();
			_digestParamSet.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0, 0, 6, parsedLen, false))
			{
				_encryptionParamSet = new Gost2814789ParamSet();
				_encryptionParamSet.Decode(buffer, true, parsedLen.Value);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			int num2;
			var len = 0;

			if (_encryptionParamSet != null)
			{
				num2 = _encryptionParamSet.Encode(buffer, true);
				len += num2;
			}

			num2 = _digestParamSet.Encode(buffer, true);
			len += num2;

			num2 = _publicKeyParamSet.Encode(buffer, true);
			len += num2;

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			_publicKeyParamSet = null;
			_digestParamSet = null;
			_encryptionParamSet = null;
		}
	}
}