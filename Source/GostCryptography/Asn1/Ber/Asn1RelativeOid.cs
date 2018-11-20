using System;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1RelativeOid : Asn1ObjectIdentifier
	{
		public new static readonly Asn1Tag Tag = new Asn1Tag(0, 0, RelativeOidTypeCode);


		public Asn1RelativeOid()
		{
		}

		public Asn1RelativeOid(OidValue oidValue)
			: base(oidValue)
		{
		}


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var len = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			OidValue = OidValue.FromArray(buffer.DecodeRelOidContents(len));
			buffer.TypeCode = RelativeOidTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (OidValue.Items.Length < 1)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
			}

			var len = 0;

			for (var i = OidValue.Items.Length - 1; i >= 0; i--)
			{
				len += buffer.EncodeIdentifier(OidValue.Items[i]);
			}

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			var len = 0;

			foreach (var i in OidValue.Items)
			{
				len += Asn1RunTime.GetIdentBytesCount(i);
			}

			if (explicitTagging)
			{
				outs.EncodeTag(Tag);
			}

			outs.EncodeLength(len);

			foreach (var i in OidValue.Items)
			{
				outs.EncodeIdentifier(i);
			}
		}
	}
}