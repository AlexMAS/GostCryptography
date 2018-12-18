using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1CerOutputStream : Asn1BerOutputStream
	{
		public Asn1CerOutputStream(Stream outputStream)
			: base(outputStream)
		{
		}

		public Asn1CerOutputStream(Stream outputStream, int bufSize)
			: base(outputStream, bufSize)
		{
		}

		public override void Encode(Asn1Type type, bool explicitTagging)
		{
			type.Encode(this, explicitTagging);
		}

		public override void EncodeBitString(byte[] value, int numbits, bool explicitTagging, Asn1Tag tag)
		{
			if ((((numbits + 7) / 8) + 1) <= 0x3e8)
			{
				base.EncodeBitString(value, numbits, explicitTagging, tag);
			}
			else
			{
				if (explicitTagging)
				{
					EncodeTagAndIndefLen(Asn1BitString.Tag.Class, 0x20, Asn1BitString.Tag.IdCode);
				}
				else
				{
					OutputStream.WriteByte(0x80);
				}

				var num = (numbits + 7) / 8;
				var num2 = numbits % 8;

				if (num2 != 0)
				{
					num2 = 8 - num2;
					value[num - 1] = (byte)(value[num - 1] & ((byte)~((1 << num2) - 1)));
				}

				for (var i = 0; i < num; i += 0x3e8)
				{
					var len = num - i;

					if (len > 0x3e8)
					{
						len = 0x3e8;
						EncodeTagAndLength(Asn1BitString.Tag, len);
					}
					else
					{
						EncodeTagAndLength(Asn1BitString.Tag, len + 1);
						OutputStream.WriteByte((byte)num2);
					}

					if (len > 0)
					{
						OutputStream.Write(value, i, len);
					}
				}

				EncodeEoc();
			}
		}

		public override void EncodeBmpString(string value, bool explicitTagging, Asn1Tag tag)
		{
			if ((value == null) || (value.Length <= 500))
			{
				base.EncodeBmpString(value, explicitTagging, tag);
			}
			else
			{
				if (explicitTagging)
				{
					EncodeTagAndIndefLen(Asn1BmpString.Tag.Class, 0x20, Asn1BmpString.Tag.IdCode);
				}
				else
				{
					OutputStream.WriteByte(0x80);
				}

				for (var i = 0; i < value.Length; i += 500)
				{
					var num2 = value.Length - i;

					if (num2 > 500)
					{
						num2 = 500;
					}

					EncodeTagAndLength(Asn1OctetString.Tag, num2 * 2);

					for (var j = 0; j < num2; j++)
					{
						var num5 = value[j + i];
						var num4 = num5 / 0x100;

						var num3 = num5 % 0x100;
						OutputStream.WriteByte((byte)num4);
						OutputStream.WriteByte((byte)num3);
					}
				}

				EncodeEoc();
			}
		}

		public override void EncodeCharString(string value, bool explicitTagging, Asn1Tag tag)
		{
			if ((value == null) || (value.Length <= 0x3e8))
			{
				base.EncodeCharString(value, explicitTagging, tag);
			}
			else
			{
				var data = Asn1Util.ToByteArray(value);

				if (explicitTagging)
				{
					EncodeTag(tag.Class, 0x20, tag.IdCode);
				}

				EncodeOctetString(data, false, tag);
			}
		}

		public override void EncodeOctetString(byte[] value, bool explicitTagging, Asn1Tag tag)
		{
			if ((value == null) || (value.Length <= 0x3e8))
			{
				base.EncodeOctetString(value, explicitTagging, tag);
			}
			else
			{
				if (explicitTagging)
				{
					EncodeTagAndIndefLen(Asn1OctetString.Tag.Class, 0x20, Asn1OctetString.Tag.IdCode);
				}
				else
				{
					OutputStream.WriteByte(0x80);
				}

				for (var i = 0; i < value.Length; i += 0x3e8)
				{
					var len = value.Length - i;

					if (len > 0x3e8)
					{
						len = 0x3e8;
					}

					EncodeTagAndLength(Asn1OctetString.Tag, len);
					Write(value, i, len);
				}

				EncodeEoc();
			}
		}

		public virtual void EncodeStringTag(int nbytes, Asn1Tag tag)
		{
			if (nbytes <= 0x3e8)
			{
				EncodeTag(tag);
			}
			else
			{
				EncodeTag(tag.Class, 0x20, tag.IdCode);
			}
		}

		public virtual void EncodeStringTag(int nbytes, short tagClass, short tagForm, int tagIdCode)
		{
			if (nbytes <= 0x3e8)
			{
				EncodeTag(new Asn1Tag(tagClass, tagForm, tagIdCode));
			}
			else
			{
				EncodeTag(tagClass, 0x20, tagIdCode);
			}
		}

		public override void EncodeUnivString(int[] value, bool explicitTagging, Asn1Tag tag)
		{
			if ((value == null) || (value.Length <= 250))
			{
				base.EncodeUnivString(value, explicitTagging, tag);
			}
			else
			{
				if (explicitTagging)
				{
					EncodeTagAndIndefLen(Asn1UniversalString.Tag.Class, 0x20, Asn1UniversalString.Tag.IdCode);
				}
				else
				{
					OutputStream.WriteByte(0x80);
				}

				for (var i = 0; i < value.Length; i += 250)
				{
					var num2 = value.Length - i;

					if (num2 > 250)
					{
						num2 = 250;
					}

					EncodeTagAndLength(Asn1OctetString.Tag, num2 * 4);

					for (int j = 0; j < num2; j++)
					{
						var number = value[j + i];

						OutputStream.WriteByte((byte)(Asn1Util.UrShift(number, 0x18) & 0xff));
						OutputStream.WriteByte((byte)(Asn1Util.UrShift(number, 0x10) & 0xff));
						OutputStream.WriteByte((byte)(Asn1Util.UrShift(number, 8) & 0xff));
						OutputStream.WriteByte((byte)(number & 0xff));
					}
				}

				EncodeEoc();
			}
		}
	}
}