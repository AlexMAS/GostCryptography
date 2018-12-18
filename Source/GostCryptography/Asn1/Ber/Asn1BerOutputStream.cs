using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1BerOutputStream : Asn1OutputStream
	{
		private static readonly byte[] Eoc = new byte[2];

		public Asn1BerOutputStream(Stream outputStream)
			: base(new BufferedStream(outputStream))
		{
		}

		public Asn1BerOutputStream(Stream outputStream, int bufSize)
			: base((bufSize == 0) ? outputStream : new BufferedStream(outputStream, bufSize))
		{
		}

		public virtual void Encode(Asn1Type type, bool explicitTagging)
		{
			type.Encode(this, explicitTagging);
		}

		public virtual void EncodeBitString(byte[] data, int numbits, bool explicitTagging, Asn1Tag tag)
		{
			if (explicitTagging)
			{
				EncodeTag(tag);
			}

			var count = (numbits + 7) / 8;
			EncodeLength(count + 1);

			var num2 = numbits % 8;

			if (num2 != 0)
			{
				num2 = 8 - num2;
				data[count - 1] = (byte)(data[count - 1] & ((byte)~((1 << num2) - 1)));
			}

			OutputStream.WriteByte((byte)num2);

			if (count > 0)
			{
				OutputStream.Write(data, 0, count);
			}
		}

		public virtual void EncodeBmpString(string data, bool explicitTagging, Asn1Tag tag)
		{
			if (explicitTagging)
			{
				EncodeTag(tag);
			}

			if (data == null)
			{
				EncodeLength(0);
			}
			else
			{
				EncodeLength(data.Length * 2);

				var length = data.Length;

				for (var i = 0; i < length; i++)
				{
					var num3 = data[i];
					var num2 = num3 / 0x100;
					var num = num3 % 0x100;

					OutputStream.WriteByte((byte)num2);
					OutputStream.WriteByte((byte)num);
				}
			}
		}

		public virtual void EncodeCharString(string data, bool explicitTagging, Asn1Tag tag)
		{
			if (explicitTagging)
			{
				EncodeTag(tag);
			}

			if (data == null)
			{
				EncodeLength(0);
			}
			else
			{
				EncodeLength(data.Length);
				var buffer = Asn1Util.ToByteArray(data);
				OutputStream.Write(buffer, 0, buffer.Length);
			}
		}

		public virtual void EncodeEoc()
		{
			OutputStream.Write(Eoc, 0, Eoc.Length);
		}

		public virtual void EncodeIdentifier(long ident)
		{
			var number = 0x7fL;
			var identBytesCount = Asn1RunTime.GetIdentBytesCount(ident);

			number = number << (7 * identBytesCount);

			if (identBytesCount > 0)
			{
				while (identBytesCount > 0)
				{
					number = Asn1Util.UrShift(number, 7);
					identBytesCount--;

					var num3 = Asn1Util.UrShift(ident & number, identBytesCount * 7);

					if (identBytesCount != 0)
					{
						num3 |= 0x80L;
					}

					OutputStream.WriteByte((byte)num3);
				}
			}
			else
			{
				OutputStream.WriteByte(0);
			}
		}

		public virtual void EncodeIntValue(long data, bool encodeLen)
		{
			long num2;
			var num = data;
			var buffer = new byte[9];
			var len = 0;
			var length = buffer.Length;

			do
			{
				num2 = num % 0x100L;
				num /= 0x100L;

				if ((num < 0L) && (num2 != 0L))
				{
					num -= 1L;
				}

				buffer[--length] = (byte)num2;
				len++;
			}
			while ((num != 0L) && (num != -1L));

			if ((data > 0L) && ((num2 & 0x80L) == 0x80L))
			{
				buffer[--length] = 0;
				len++;
			}
			else if ((data < 0L) && ((num2 & 0x80L) == 0L))
			{
				buffer[--length] = 0xff;
				len++;
			}

			if (encodeLen)
			{
				EncodeLength(len);
			}

			OutputStream.Write(buffer, length, len);
		}

		public virtual void EncodeLength(int len)
		{
			if (len >= 0)
			{
				var bytesCount = Asn1Util.GetBytesCount(len);

				if (len > 0x7f)
				{
					OutputStream.WriteByte((byte)(bytesCount | 0x80));
				}
				for (var i = (8 * bytesCount) - 8; i >= 0; i -= 8)
				{
					var num3 = (byte)((len >> i) & 0xff);
					OutputStream.WriteByte(num3);
				}
			}
			else if (len == Asn1Status.IndefiniteLength)
			{
				OutputStream.WriteByte(0x80);
			}
		}

		public virtual void EncodeOctetString(byte[] data, bool explicitTagging, Asn1Tag tag)
		{
			if (explicitTagging)
			{
				EncodeTag(tag);
			}
			if (data == null)
			{
				EncodeLength(0);
			}
			else
			{
				EncodeLength(data.Length);
				OutputStream.Write(data, 0, data.Length);
			}
		}

		public virtual void EncodeTag(Asn1Tag tag)
		{
			var num = (byte)(((byte)tag.Class) | ((byte)tag.Form));
			if (tag.IdCode < 0x1f)
			{
				OutputStream.WriteByte((byte)(num | tag.IdCode));
			}
			else
			{
				OutputStream.WriteByte((byte)(num | 0x1f));
				EncodeIdentifier(tag.IdCode);
			}
		}

		public virtual void EncodeTag(short tagClass, short tagForm, int tagIdCode)
		{
			EncodeTag(new Asn1Tag(tagClass, tagForm, tagIdCode));
		}

		public virtual void EncodeTagAndIndefLen(Asn1Tag tag)
		{
			EncodeTag(tag);
			OutputStream.WriteByte(0x80);
		}

		public virtual void EncodeTagAndIndefLen(short tagClass, short tagForm, int tagIdCode)
		{
			EncodeTag(new Asn1Tag(tagClass, tagForm, tagIdCode));
			OutputStream.WriteByte(0x80);
		}

		public virtual void EncodeTagAndLength(Asn1Tag tag, int len)
		{
			EncodeTag(tag);
			EncodeLength(len);
		}

		public virtual void EncodeUnivString(int[] data, bool explicitTagging, Asn1Tag tag)
		{
			if (explicitTagging)
			{
				EncodeTag(tag);
			}
			if (data == null)
			{
				EncodeLength(0);
			}
			else
			{
				EncodeLength(data.Length * 4);
				var length = data.Length;

				for (var i = 0; i < length; ++i)
				{
					var number = data[i];
					OutputStream.WriteByte((byte)(Asn1Util.UrShift(number, 0x18) & 0xff));
					OutputStream.WriteByte((byte)(Asn1Util.UrShift(number, 0x10) & 0xff));
					OutputStream.WriteByte((byte)(Asn1Util.UrShift(number, 8) & 0xff));
					OutputStream.WriteByte((byte)(number & 0xff));
				}
			}
		}
	}
}