using System;
using System.IO;
using System.Text;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1BerEncodeBuffer : Asn1EncodeBuffer
	{
		public Asn1BerEncodeBuffer()
		{
			ByteIndex = SizeIncrement - 1;
		}

		public Asn1BerEncodeBuffer(int sizeIncrement)
			: base(sizeIncrement)
		{
			ByteIndex = SizeIncrement - 1;
		}

		public virtual MemoryStream ByteArrayInputStream
		{
			get
			{
				var index = ByteIndex + 1;
				return new MemoryStream(Data, index, Data.Length - index);
			}
		}

		public override byte[] MsgCopy
		{
			get
			{
				var sourceIndex = ByteIndex + 1;
				var length = Data.Length - sourceIndex;
				var destinationArray = new byte[length];

				Array.Copy(Data, sourceIndex, destinationArray, 0, length);

				return destinationArray;
			}
		}

		public override int MsgLength
		{
			get
			{
				var num = ByteIndex + 1;
				return (Data.Length - num);
			}
		}

		public virtual void BinDump()
		{
			BinDump(null);
		}

		public override void BinDump(StreamWriter outs, string varName)
		{
			var buffer = new Asn1BerDecodeBuffer(ByteArrayInputStream);

			try
			{
				buffer.Parse(new Asn1BerMessageDumpHandler(outs));
			}
			catch (Exception exception)
			{
				Console.Out.WriteLine(exception.Message);
				Console.Error.Write(exception.StackTrace);
				Console.Error.Flush();
			}
		}

		protected internal override void CheckSize(int bytesRequired)
		{
			if (bytesRequired > (ByteIndex + 1))
			{
				var num = ((bytesRequired - 1) / SizeIncrement) + 1;
				var num2 = num * SizeIncrement;
				var destinationArray = new byte[Data.Length + num2];
				var destinationIndex = (ByteIndex + num2) + 1;
				var length = Data.Length - (ByteIndex + 1);

				Array.Copy(Data, ByteIndex + 1, destinationArray, destinationIndex, length);

				Data = destinationArray;
				ByteIndex = destinationIndex - 1;
			}
		}

		public override void Copy(byte data)
		{
			if (ByteIndex < 0)
			{
				CheckSize(1);
			}

			Data[ByteIndex--] = data;
		}

		public override void Copy(byte[] data)
		{
			CheckSize(data.Length);
			ByteIndex -= data.Length;

			Array.Copy(data, 0, Data, ByteIndex + 1, data.Length);
		}

		public virtual void Copy(string data)
		{
			var length = data.Length;
			CheckSize(length);
			ByteIndex -= length;

			for (var i = 0; i < length; ++i)
			{
				Data[(ByteIndex + i) + 1] = (byte)data[i];
			}
		}

		public virtual void Copy(byte[] data, int startOffset, int length)
		{
			CheckSize(length);
			ByteIndex -= length;

			Array.Copy(data, startOffset, Data, ByteIndex + 1, length);
		}

		public virtual int EncodeIdentifier(int ident)
		{
			var flag = true;
			var num = 0;
			var num2 = ident;

			do
			{
				if (ByteIndex < 0)
				{
					CheckSize(1);
				}

				Data[ByteIndex] = (byte)(num2 % 0x80);

				if (!flag)
				{
					Data[ByteIndex] = (byte)(Data[ByteIndex] | 0x80);
				}
				else
				{
					flag = false;
				}

				ByteIndex--;
				num2 /= 0x80;
				num++;

			}
			while (num2 > 0);

			return num;
		}

		public virtual int EncodeIntValue(long ivalue)
		{
			long num2;
			long num = ivalue;

			var num3 = 0;

			do
			{
				num2 = num % 0x100L;
				num /= 0x100L;

				if ((num < 0L) && (num2 != 0L))
				{
					num -= 1L;
				}

				Copy((byte)num2);

				num3++;
			}
			while ((num != 0L) && (num != -1L));

			if ((ivalue > 0L) && ((num2 & 0x80L) == 0x80L))
			{
				Copy(0);
				num3++;
				return num3;
			}

			if ((ivalue < 0L) && ((num2 & 0x80L) == 0L))
			{
				Copy(0xff);
				num3++;
			}

			return num3;
		}

		public virtual int EncodeLength(int len)
		{
			var num = 0;

			bool flag;

			if (len >= 0)
			{
				flag = len > 0x7f;

				var num2 = len;

				do
				{
					if (ByteIndex < 0)
					{
						CheckSize(1);
					}

					Data[ByteIndex--] = (byte)(num2 % 0x100);
					num++;
					num2 /= 0x100;
				}
				while (num2 > 0);
			}
			else
			{
				flag = len == Asn1Status.IndefiniteLength;
			}

			if (flag)
			{
				if (ByteIndex < 0)
				{
					CheckSize(1);
				}

				Data[ByteIndex--] = (byte)(num | 0x80);
				num++;
			}

			return num;
		}

		public virtual int EncodeTag(Asn1Tag tag)
		{
			var num = (byte)(((byte)tag.Class) | ((byte)tag.Form));
			var num2 = 0;

			if (tag.IdCode < 0x1f)
			{
				Copy((byte)(num | tag.IdCode));
				num2++;
				return num2;
			}

			num2 += EncodeIdentifier(tag.IdCode);
			Copy((byte)(num | 0x1f));
			num2++;

			return num2;
		}

		public virtual int EncodeTagAndLength(Asn1Tag tag, int len)
		{
			return (EncodeLength(len) + EncodeTag(tag));
		}

		public virtual int EncodeTagAndLength(short tagClass, short tagForm, int tagIdCode, int len)
		{
			var tag = new Asn1Tag(tagClass, tagForm, tagIdCode);
			return EncodeTagAndLength(tag, len);
		}

		public override Stream GetInputStream()
		{
			return ByteArrayInputStream;
		}

		public override void Reset()
		{
			ByteIndex = Data.Length - 1;
		}

		public override string ToString()
		{
			var num = ByteIndex + 1;
			var num2 = Data.Length - num;
			var str = new StringBuilder("").ToString();

			for (var i = 0; i < num2; ++i)
			{
				str = str + Asn1Util.ToHexString(Data[i + num]);
			}

			return str;
		}

		public override void Write(Stream outs)
		{
			var offset = ByteIndex + 1;
			outs.Write(Data, offset, Data.Length - offset);
		}
	}
}