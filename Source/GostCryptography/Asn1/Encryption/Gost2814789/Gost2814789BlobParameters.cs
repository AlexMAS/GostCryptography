using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Encryption.Gost2814789
{
	class Gost2814789BlobParameters : Asn1Type
	{
		public Gost2814789ParamSet EncryptionParamSet;

		private Asn1OpenExt _extElem1;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptionParamSet = new Gost2814789ParamSet();
			EncryptionParamSet.Decode(buffer, true, parsedLen.Value);

			if (!context.Expired())
			{
				if (buffer.PeekTag().Equals(0, 0, ObjectIdentifierTypeCode))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1SeqOrderException);
				}

				_extElem1 = new Asn1OpenExt();

				while (!context.Expired())
				{
					_extElem1.DecodeComponent(buffer);
				}
			}
			else
			{
				_extElem1 = null;
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			int num2;
			var len = 0;

			if (_extElem1 != null)
			{
				num2 = _extElem1.Encode(buffer, false);
				len += num2;
			}

			num2 = EncryptionParamSet.Encode(buffer, true);
			len += num2;

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			EncryptionParamSet = null;

			_extElem1 = null;
		}
	}
}