using System;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	public static class Asn1Value
	{
		private static byte[] AllocBitArray(int numbits)
		{
			var num = numbits / 8;

			if ((numbits % 8) != 0)
			{
				num++;
			}

			return new byte[num];
		}

		public static byte[] ParseString(string data)
		{
			return ParseString(data, null);
		}

		public static byte[] ParseString(string data, IntHolder numbits)
		{
			char ch;
			int num;
			int num2;
			int num3;
			int num4;
			int num5;

			char ch2 = data[0];
			byte[] buffer;

			switch (ch2)
			{
				case '\'':
				case '"':
					if (!data.EndsWith("B"))
					{
						if (data.EndsWith("H"))
						{
							var builder = new StringBuilder();
							num3 = (data.Length - 3) * 4;
							buffer = AllocBitArray(num3);
							builder.Length = 2;
							num = 1;
							num2 = 0;
							ch = '\0';

							while ((num < data.Length) && (ch != ch2))
							{
								ch = data[num++];

								if (ch != ch2)
								{
									builder[0] = ch;
									ch = (num >= data.Length) ? '0' : data[num];
									builder[1] = (ch == ch2) ? '0' : ch;
									buffer[num2++] = (byte)Convert.ToInt32(builder.ToString(), 0x10);
								}

								num++;
							}
						}
						else
						{
							if (data[data.Length - 1] != ch2)
							{
								throw ExceptionUtility.CryptographicException(Resources.Asn1ValueParseException, data, data.Length - 1);
							}

							num3 = (data.Length - 2) * 8;
							buffer = AllocBitArray(num3);
							num = 1;
							ch = '\0';

							while ((num < data.Length) && (ch != ch2))
							{
								ch = data[num];

								if (ch != ch2)
								{
									buffer[num - 1] = (byte)ch;
								}

								num++;
							}
						}

						return SetNumBits(numbits, num3, buffer);
					}

					num3 = data.Length - 3;
					buffer = AllocBitArray(num3);
					num5 = 0x80;
					num = 1;
					num4 = 0;
					num2 = 0;

					while (num < data.Length)
					{
						ch = data[num];

						if (ch == '1')
						{
							num4 |= num5;
						}
						else
						{
							if (ch == ch2)
							{
								break;
							}
							if (ch != '0')
							{
								ExceptionUtility.CryptographicException(Resources.Asn1ValueParseException, data, num);
							}
						}

						num5 = num5 >> 1;

						if (num5 == 0)
						{
							buffer[num2++] = (byte)num4;
							num5 = 0x80;
							num4 = 0;
						}

						num++;
					}
					break;
				default:
					num3 = data.Length * 8;
					buffer = AllocBitArray(num3);
					num = 0;

					while (num < data.Length)
					{
						ch = data[num];
						buffer[num] = (byte)ch;
						num++;
					}

					return SetNumBits(numbits, num3, buffer);
			}

			if (num5 != 0x80)
			{
				buffer[num2] = (byte)num4;
			}

			return SetNumBits(numbits, num3, buffer);
		}

		private static byte[] SetNumBits(IntHolder numbits, int num3, byte[] buffer)
		{
			if (numbits != null)
			{
				numbits.Value = num3;
			}

			return buffer;
		}
	}
}