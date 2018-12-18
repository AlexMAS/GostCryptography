using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1BerDecodeContext
	{
		private readonly int _decBufByteCount;
		private readonly Asn1BerDecodeBuffer _decodeBuffer;
		private readonly int _elemLength;
		private readonly Asn1Tag _tagHolder;

		public Asn1BerDecodeContext(Asn1BerDecodeBuffer decodeBuffer, int elemLength)
		{
			_decodeBuffer = decodeBuffer;
			_decBufByteCount = decodeBuffer.ByteCount;
			_elemLength = elemLength;
			_tagHolder = new Asn1Tag();
		}

		public virtual bool Expired()
		{
			if (_elemLength == Asn1Status.IndefiniteLength)
			{
				var parsedLen = new IntHolder();
				var flag = _decodeBuffer.MatchTag(0, 0, 0, null, parsedLen);

				if (flag)
				{
					_decodeBuffer.Reset();
				}

				return flag;
			}

			var num = _decodeBuffer.ByteCount - _decBufByteCount;

			return (num >= _elemLength);
		}

		public virtual bool MatchElemTag(Asn1Tag tag, IntHolder parsedLen, bool advance)
		{
			return MatchElemTag(tag.Class, tag.Form, tag.IdCode, parsedLen, advance);
		}

		public virtual bool MatchElemTag(short tagClass, short tagForm, int tagIdCode, IntHolder parsedLen, bool advance)
		{
			if (Expired())
			{
				return false;
			}

			var flag = _decodeBuffer.MatchTag(tagClass, tagForm, tagIdCode, _tagHolder, parsedLen);

			if ((_elemLength != Asn1Status.IndefiniteLength) && (parsedLen.Value != Asn1Status.IndefiniteLength))
			{
				var num = _decodeBuffer.ByteCount - _decBufByteCount;

				if ((parsedLen.Value < 0) || (parsedLen.Value > (_elemLength - num)))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
				}
			}

			if (flag && !advance)
			{
				_decodeBuffer.Reset();
			}

			return flag;
		}
	}
}