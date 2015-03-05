using System;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	class Asn1RelativeOid : Asn1ObjectIdentifier
	{
		public new static readonly Asn1Tag Tag = new Asn1Tag(0, 0, RelativeOidTypeCode);

		public Asn1RelativeOid()
		{
		}

		public Asn1RelativeOid(int[] value)
			: base(value)
		{
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var llen = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			Value = buffer.DecodeRelOidContents(llen);
			buffer.TypeCode = RelativeOidTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (Value.Length < 1)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
			}

			var len = 0;

			for (var i = Value.Length - 1; i >= 0; i--)
			{
				len += buffer.EncodeIdentifier(Value[i]);
			}

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			int num;
			var len = 0;

			for (num = 0; num < Value.Length; num++)
			{
				len += Asn1RunTime.GetIdentBytesCount(Value[num]);
			}

			if (explicitTagging)
			{
				outs.EncodeTag(Tag);
			}

			outs.EncodeLength(len);

			for (num = 0; num < Value.Length; num++)
			{
				outs.EncodeIdentifier(Value[num]);
			}
		}
	}
}