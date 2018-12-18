using System;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1ObjectIdentifier : Asn1Type
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, ObjectIdentifierTypeCode);


		[NonSerialized]
		protected OidValue OidValue;

		public OidValue Oid => OidValue;


		public Asn1ObjectIdentifier()
		{
			OidValue = null;
		}

		public Asn1ObjectIdentifier(OidValue oidValue)
		{
			OidValue = oidValue;
		}


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var len = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;

			if (len <= 0)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
			}

			OidValue = OidValue.FromArray(buffer.DecodeOidContents(len));
			buffer.TypeCode = ObjectIdentifierTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			if (((OidValue.Items.Length < 2) || (OidValue.Items[0] > 2)) || ((OidValue.Items[0] != 2) && (OidValue.Items[1] > 0x27)))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
			}

			var len = 0;

			for (var i = OidValue.Items.Length - 1; i >= 1; i--)
			{
				len += buffer.EncodeIdentifier((i == 1) ? ((OidValue.Items[0] * 40) + OidValue.Items[1]) : OidValue.Items[i]);
			}

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			if (((OidValue.Items.Length < 2) || (OidValue.Items[0] > 2)) || ((OidValue.Items[0] != 2) && (OidValue.Items[1] > 0x27)))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidObjectIdException);
			}

			var len = 1;

			for (var i = 2; i < OidValue.Items.Length; i++)
			{
				len += Asn1RunTime.GetIdentBytesCount(OidValue.Items[i]);
			}

			if (explicitTagging)
			{
				outs.EncodeTag(Tag);
			}

			outs.EncodeLength(len);
			var ident = (OidValue.Items[0] * 40) + OidValue.Items[1];
			outs.EncodeIdentifier(ident);

			for (var i = 2; i < OidValue.Items.Length; i++)
			{
				outs.EncodeIdentifier(OidValue.Items[i]);
			}
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}

			if (!(obj is Asn1ObjectIdentifier))
			{
				return false;
			}

			var other = (Asn1ObjectIdentifier)obj;

			if (OidValue == other.OidValue)
			{
				return true;
			}

			if (OidValue == null || other.OidValue == null)
			{
				return false;
			}

			return OidValue.Equals(other.OidValue);
		}

		public override int GetHashCode()
		{
			return OidValue?.GetHashCode() ?? base.GetHashCode();
		}

		public override string ToString()
		{
			return OidValue?.ToString() ?? base.ToString();
		}
	}
}