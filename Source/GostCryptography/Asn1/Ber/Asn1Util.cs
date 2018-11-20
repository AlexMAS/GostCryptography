using System;
using System.Collections;
using System.IO;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	public static class Asn1Util
	{
		private static readonly byte[] Base64DecodeTable =
		{
			0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
			60, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6,
			7, 8, 9, 10, 11, 12, 13, 14, 15, 0x10, 0x11, 0x12, 0x13, 20, 0x15, 0x16,
			0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 30, 0x1f, 0x20,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 40, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
			0x31, 50, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff
		};

		private static readonly byte[] Base64EncodeTable =
		{
			0x41, 0x42, 0x43, 0x44, 0x45, 70, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 80,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 90, 0x61, 0x62, 0x63, 100, 0x65, 0x66,
			0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 110, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
			0x77, 120, 0x79, 0x7a, 0x30, 0x31, 50, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f
		};

		public static string BcdToString(byte[] bcd)
		{
			var index = 0;
			var builder = new StringBuilder(bcd.Length * 2);

			for (var i = 0; i < (bcd.Length * 2); i++)
			{
				byte num3;

				if ((i % 2) == 0)
				{
					num3 = (byte)(bcd[index] & 15);
				}
				else
				{
					num3 = (byte)UrShift(bcd[index++], 4);
				}

				if (num3 == 15)
				{
					break;
				}

				builder.Append((num3 < 10) ? ((char)(num3 + 0x30)) : ((char)((num3 + 0x41) - 10)));
			}

			return builder.ToString();
		}

		public static byte[] DecodeBase64Array(byte[] srcArray)
		{
			var num = srcArray.Length / 4;

			if ((4 * num) != srcArray.Length)
			{
				throw ExceptionUtility.Argument("srcArray", Resources.Asn1InvalidEncodedDataLength);
			}

			var num2 = 0;
			var num3 = num;

			if (srcArray.Length != 0)
			{
				if (srcArray[srcArray.Length - 1] == 0x3d)
				{
					num2++;
					num3--;
				}
				if (srcArray[srcArray.Length - 2] == 0x3d)
				{
					num2++;
				}
			}

			var buffer = new byte[(3 * num) - num2];
			var num4 = 0;
			var num5 = 0;

			for (var i = 0; i < num3; i++)
			{
				var num7 = DecodeBase64Char(srcArray[num4++]);
				var num8 = DecodeBase64Char(srcArray[num4++]);
				var num9 = DecodeBase64Char(srcArray[num4++]);
				var num10 = DecodeBase64Char(srcArray[num4++]);

				buffer[num5++] = (byte)((num7 << 2) | (num8 >> 4));
				buffer[num5++] = (byte)((num8 << 4) | (num9 >> 2));
				buffer[num5++] = (byte)((num9 << 6) | num10);
			}

			if (num2 != 0)
			{
				var num11 = DecodeBase64Char(srcArray[num4++]);
				var num12 = DecodeBase64Char(srcArray[num4++]);

				buffer[num5++] = (byte)((num11 << 2) | (num12 >> 4));

				if (num2 == 1)
				{
					var num13 = DecodeBase64Char(srcArray[num4++]);
					buffer[num5++] = (byte)((num12 << 4) | (num13 >> 2));
				}
			}

			return buffer;
		}

		private static int DecodeBase64Char(byte c)
		{
			var num = (c < 0x80) ? Base64DecodeTable[c - 40] : -1;

			if (num < 0)
			{
				throw ExceptionUtility.Argument("c", Resources.Asn1IllegalCharacter, c);
			}

			return num;
		}

		public static byte[] EncodeBase64Array(byte[] srcArray)
		{
			var num = srcArray.Length / 3;
			var num2 = srcArray.Length - (3 * num);
			var num3 = 4 * ((srcArray.Length + 2) / 3);
			var buffer = new byte[num3];
			var num4 = 0;
			var num5 = 0;

			for (var i = 0; i < num; i++)
			{
				var num7 = srcArray[num4++] & 0xff;
				var num8 = srcArray[num4++] & 0xff;
				var num9 = srcArray[num4++] & 0xff;

				buffer[num5++] = Base64EncodeTable[num7 >> 2];
				buffer[num5++] = Base64EncodeTable[((num7 << 4) & 0x3f) | (num8 >> 4)];
				buffer[num5++] = Base64EncodeTable[((num8 << 2) & 0x3f) | (num9 >> 6)];
				buffer[num5++] = Base64EncodeTable[num9 & 0x3f];
			}

			if (num2 != 0)
			{
				var num10 = srcArray[num4++] & 0xff;
				buffer[num5++] = Base64EncodeTable[num10 >> 2];

				if (num2 == 1)
				{
					buffer[num5++] = Base64EncodeTable[(num10 << 4) & 0x3f];
					buffer[num5++] = 0x3d;
					buffer[num5++] = 0x3d;

					return buffer;
				}

				var num11 = srcArray[num4++] & 0xff;
				buffer[num5++] = Base64EncodeTable[((num10 << 4) & 0x3f) | (num11 >> 4)];
				buffer[num5++] = Base64EncodeTable[(num11 << 2) & 0x3f];
				buffer[num5++] = 0x3d;
			}

			return buffer;
		}

		public static byte[] GetAddressBytes(string ipaddress)
		{
			var index = 0;
			var buffer = new byte[4];
			var tokenizer = new Tokenizer(ipaddress, ".");

			try
			{
				while (tokenizer.HasMoreTokens())
				{
					buffer[index] = Convert.ToByte(tokenizer.NextToken());
					index++;
				}
			}
			catch (Exception)
			{
			}

			return buffer;
		}

		public static int GetBytesCount(long val)
		{
			return Asn1RunTime.GetLongBytesCount(val);
		}

		public static int GetUlongBytesCount(long val)
		{
			return Asn1RunTime.GetUlongBytesCount(val);
		}

		public static byte[] StringToBcd(string str)
		{
			int num2;
			var buffer = new byte[(str.Length + 1) / 2];
			byte num = 0;
			var num3 = num2 = 0;

			while (num3 < str.Length)
			{
				var c = char.ToUpper(str[num3]);
				var flag = char.IsDigit(c);

				if (!flag && ((c < 'A') || (c >= 'F')))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1ValueParseException, str, num3);
				}

				if ((num3 % 2) != 0)
				{
					num = (byte)(num | ((byte)(((byte)((flag != null) ? (c - 0x30) : ((c - 0x41) + 10))) << 4)));
					buffer[num2++] = num;
				}
				else
				{
					num = flag ? ((byte)(c - '0')) : ((byte)((c - 'A') + 10));
				}

				num3++;
			}

			if ((num3 % 2) != 0)
			{
				buffer[num2++] = (byte)(num | 240);
			}

			return buffer;
		}

		public static void ToArray(ICollection c, object[] objects)
		{
			var num = 0;
			var enumerator = c.GetEnumerator();

			while (enumerator.MoveNext())
			{
				objects[num++] = enumerator.Current;
			}
		}

		public static byte[] ToByteArray(string sourceString)
		{
			return Encoding.UTF8.GetBytes(sourceString);
		}

		public static char[] ToCharArray(byte[] byteArray)
		{
			return Encoding.UTF8.GetChars(byteArray);
		}

		public static string ToHexString(byte b)
		{
			var builder = new StringBuilder(4);
			var str = Convert.ToString(b, 0x10);
			var length = str.Length;

			if (length < 2)
			{
				builder.Append('0');
				builder.Append(str);
			}
			else if (length > 2)
			{
				builder.Append(str[length - 2]);
				builder.Append(str[length - 1]);
			}
			else
			{
				builder.Append(str);
			}

			return builder.ToString();
		}

		public static string ToHexString(byte[] b, int offset, int nbytes)
		{
			var builder = new StringBuilder(nbytes * 4);

			for (var i = 0; i < nbytes; i++)
			{
				builder.Append(ToHexString(b[offset + i]));
				builder.Append(" ");
			}

			return builder.ToString();
		}

		public static int UrShift(int number, int bits)
		{
			if (number >= 0)
			{
				return (number >> bits);
			}

			return ((number >> bits) + (2 << ~bits));
		}

		public static int UrShift(int number, long bits)
		{
			return UrShift(number, (int)bits);
		}

		public static long UrShift(long number, int bits)
		{
			if (number >= 0L)
			{
				return (number >> bits);
			}

			return ((number >> bits) + (2L << ~bits));
		}

		public static long UrShift(long number, long bits)
		{
			return UrShift(number, (int)bits);
		}

		public static void WriteStackTrace(Exception throwable, TextWriter stream)
		{
			stream.Write(throwable.StackTrace);
			stream.Flush();
		}
	}
}