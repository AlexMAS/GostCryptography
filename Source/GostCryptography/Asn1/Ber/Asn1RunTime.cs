using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	public static class Asn1RunTime
	{
		public const int LicBer = 1;
		public const int LicPer = 2;
		public const int LicXer = 4;
		public const long Bit0Mask = -9223372036854775808L;

		public static long DecodeIntValue(Asn1DecodeBuffer buffer, int length, bool signExtend)
		{
			var num = 0L;

			if (length > 8)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1IntegerValueIsTooLarge);
			}

			for (var i = 0; i < length; i++)
			{
				var num2 = buffer.ReadByte();

				if (num2 < 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
				}

				if ((i == 0) && signExtend)
				{
					num = (num2 > 0x7f) ? -1 : 0;
				}

				num = (num * 0x100L) + num2;
			}

			return num;
		}

		public static int GetIdentBytesCount(long ident)
		{
			if (ident < 0x80L)
			{
				return 1;
			}

			if (ident < 0x4000L)
			{
				return 2;
			}

			if (ident < 0x200000L)
			{
				return 3;
			}

			if (ident < 0x10000000L)
			{
				return 4;
			}

			if (ident < 0x800000000L)
			{
				return 5;
			}

			if (ident < 0x40000000000L)
			{
				return 6;
			}

			if (ident < 0x2000000000000L)
			{
				return 7;
			}

			if (ident < 0x100000000000000L)
			{
				return 8;
			}

			return 9;
		}

		public static int GetLongBitCount(long ivalue)
		{
			var num = ivalue & Bit0Mask;
			var num2 = 0;

			if (ivalue != 0L)
			{
				while ((ivalue & Bit0Mask) == num)
				{
					num2++;
					ivalue = ivalue << 1;
				}

				if (num == Bit0Mask)
				{
					num2--;
				}

				return (0x40 - num2);
			}

			return 0;
		}

		public static int GetLongBytesCount(long value)
		{
			var num = 0x7f80000000000000L;
			var num2 = 8;

			if (value < 0L)
			{
				value ^= -1L;
			}

			while ((num2 > 1) && ((value & num) == 0L))
			{
				num = num >> 8;
				num2--;
			}

			return num2;
		}

		public static int GetUlongBytesCount(long value)
		{
			var number = -72057594037927936L;
			var num2 = 8;

			while ((num2 > 1) && ((value & number) == 0L))
			{
				number = Asn1Util.UrShift(number, 8);
				num2--;
			}

			return num2;
		}

		public static int IntTrailingZerosCnt(int w)
		{
			return (0x20 -
					(((w & 0xffff) != 0)
						? (((w & 0xff) != 0) ? ((((w & 15) != 0) ? (((w & 3) != 0) ? (((w & 1) != 0) ? 8 : 7) : (((w & 4) != 0) ? 6 : 5)) : (((w & 0x30) != 0) ? (((w & 0x10) != 0) ? 4 : 3) : (((w & 0x40) != 0) ? 2 : (((w & 0x80) != 0) ? 1 : 0)))) + 0x18) : (((((w = Asn1Util.UrShift(w, 8)) & 15) != 0) ? (((w & 3) != 0) ? (((w & 1) != 0) ? 8 : 7) : (((w & 4) != 0) ? 6 : 5)) : (((w & 0x30) != 0) ? (((w & 0x10) != 0) ? 4 : 3) : (((w & 0x40) != 0) ? 2 : (((w & 0x80) != 0) ? 1 : 0)))) + 0x10))
						: ((((w = Asn1Util.UrShift(w, 0x10)) & 0xff) != 0) ? ((((w & 15) != 0) ? (((w & 3) != 0) ? (((w & 1) != 0) ? 8 : 7) : (((w & 4) != 0) ? 6 : 5)) : (((w & 0x30) != 0) ? (((w & 0x10) != 0) ? 4 : 3) : (((w & 0x40) != 0) ? 2 : (((w & 0x80) != 0) ? 1 : 0)))) + 8) : ((((w = Asn1Util.UrShift(w, 8)) & 15) != 0) ? (((w & 3) != 0) ? (((w & 1) != 0) ? 8 : 7) : (((w & 4) != 0) ? 6 : 5)) : (((w & 0x30) != 0) ? (((w & 0x10) != 0) ? 4 : 3) : (((w & 0x40) != 0) ? 2 : (((w & 0x80) != 0) ? 1 : 0)))))));
		}
	}
}