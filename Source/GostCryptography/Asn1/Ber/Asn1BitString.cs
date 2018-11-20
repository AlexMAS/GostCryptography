using System;
using System.Collections;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1BitString : Asn1Type
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, BitStringTypeCode);

		[NonSerialized]
		public byte[] Value;

		[NonSerialized]
		public int NumBits;

		public Asn1BitString()
		{
			NumBits = 0;
			Value = null;
		}

		public Asn1BitString(bool[] bitValues)
		{
			AllocBitArray(bitValues.Length);

			var index = 0;
			var num4 = 0x80;
			var num = 0;
			var num2 = 0;

			while (num < bitValues.Length)
			{
				if (bitValues[num])
				{
					num2 |= num4;
				}

				num4 = num4 >> 1;

				if (num4 == 0)
				{
					Value[index++] = (byte)num2;
					num4 = 0x80;
					num2 = 0;
				}

				num++;
			}

			if (num4 != 0x80)
			{
				Value[index] = (byte)num2;
			}
		}

		public Asn1BitString(BitArray bitArray)
		{
			AllocBitArray(bitArray.Length);

			var index = 0;
			var num4 = 0x80;
			var num = 0;
			var num2 = 0;

			while (num < bitArray.Length)
			{
				if (bitArray.Get(num))
				{
					num2 |= num4;
				}

				num4 = num4 >> 1;

				if (num4 == 0)
				{
					Value[index++] = (byte)num2;
					num4 = 0x80;
					num2 = 0;
				}

				num++;
			}

			if (num4 != 0x80)
			{
				Value[index] = (byte)num2;
			}
		}

		public Asn1BitString(string value)
		{
			var numbits = new IntHolder();
			Value = Asn1Value.ParseString(value, numbits);

			NumBits = numbits.Value;
		}

		public Asn1BitString(int numBits, byte[] data)
		{
			NumBits = numBits;
			Value = data;
		}

		private void AllocBitArray(int numbits)
		{
			NumBits = numbits;

			var num = (NumBits + 7) / 8;

			if ((Value == null) || (Value.Length < num))
			{
				Value = new byte[num];
			}
		}

		public virtual void Clear(int bitIndex)
		{
			this[bitIndex] = false;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			var lastTag = buffer.LastTag;

			if ((lastTag == null) || !lastTag.Constructed)
			{
				if (elemLength < 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
				}

				if (elemLength != 0)
				{
					var num8 = elemLength - 1;
					var num7 = buffer.Read();

					if (num7 < 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1EndOfBufferException, buffer.ByteCount);
					}

					if ((num7 < 0) || (num7 > 7))
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfBitString, num7);
					}

					if ((num8 == 0) && (num7 != 0))
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidLengthException);
					}

					NumBits = (num8 * 8) - num7;
					Value = new byte[num8];
					buffer.Read(Value);
				}
				else
				{
					NumBits = 0;
					Value = null;
				}
			}
			else
			{
				var num3 = 0;
				var offset = 0;
				var index = -1;
				var num6 = 0;

				var context = new Asn1BerDecodeContext(buffer, elemLength);

				while (!context.Expired())
				{
					var nbytes = MatchTag(buffer, Tag);

					if (nbytes <= 0)
					{
						throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfConstructedValue, buffer.ByteCount);
					}

					num3 += nbytes;

					if (offset == 0)
					{
						AllocBitArray(num3 * 8);
					}
					else
					{
						ReallocBitArray(num3 * 8);
					}

					index = offset;
					buffer.Read(Value, offset, nbytes);
					offset = num3;
				}

				if (index >= 0)
				{
					num6 = Value[index];

					if (((offset - index) - 1) > 0)
					{
						Array.Copy(Value, index + 1, Value, index, (offset - index) - 1);
					}

					num3--;
				}

				if ((num6 < 0) || (num6 > 7))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidFormatOfBitString, num6);
				}

				ReallocBitArray((num3 * 8) - num6);

				if (elemLength == Asn1Status.IndefiniteLength)
				{
					MatchTag(buffer, Asn1Tag.Eoc);
				}
			}

			buffer.TypeCode = 3;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var length = (NumBits + 7) / 8;
			var num2 = NumBits % 8;

			if (num2 != 0)
			{
				num2 = 8 - num2;
				Value[length - 1] = (byte)(Value[length - 1] & ((byte)~((1 << num2) - 1)));
			}

			if (length != 0)
			{
				buffer.Copy(Value, 0, length);
			}

			buffer.Copy((byte)num2);
			length++;

			if (explicitTagging)
			{
				length += buffer.EncodeTagAndLength(Tag, length);
			}

			return length;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			outs.EncodeBitString(Value, NumBits, explicitTagging, Tag);
		}

		public override bool Equals(object value)
		{
			var str = value as Asn1BitString;

			if (str == null)
			{
				return false;
			}

			return Equals(str.NumBits, str.Value);
		}

		public virtual bool Equals(int nbits, byte[] value)
		{
			if (nbits != NumBits)
			{
				return false;
			}

			var num = ((nbits - 1) / 8) + 1;

			for (var i = 0; i < num; ++i)
			{
				if (value[i] != Value[i])
				{
					return false;
				}
			}

			return true;
		}

		public virtual bool Get(int bitno)
		{
			var index = bitno / 8;
			var num2 = 1 << (7 - (bitno % 8));

			if ((Value != null) && (Value.Length >= index))
			{
				int num3 = Value[index];
				return ((num3 & num2) != 0);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return (Value != null) ? Value.GetHashCode() : base.GetHashCode();
		}

		private void ReallocBitArray(int numbits)
		{
			NumBits = numbits;
			var num = (NumBits + 7) / 8;

			if (Value.Length != num)
			{
				var value = Value;
				Value = new byte[num];

				if (value != null)
				{
					Array.Copy(value, 0, Value, 0, Math.Min(value.Length, num));
				}
			}
		}

		public virtual void Set(int bitIndex)
		{
			Set(bitIndex, true);
		}

		public virtual void Set(int bitIndex, bool value)
		{
			var index = bitIndex / 8;
			var num2 = 1 << (7 - (bitIndex % 8));
			var num3 = index + 1;

			if (Value == null)
			{
				Value = new byte[num3];
			}
			else if (Value.Length < num3)
			{
				var destinationArray = new byte[num3];
				Array.Copy(Value, 0, destinationArray, 0, Value.Length);
				Value = destinationArray;
			}

			int num4 = Value[index];
			num4 = value ? (num4 | num2) : (num4 & ~num2);
			Value[index] = (byte)num4;

			if ((bitIndex + 1) > NumBits)
			{
				NumBits = bitIndex + 1;
			}
		}

		public virtual bool[] ToBoolArray()
		{
			var flagArray = new bool[NumBits];

			var num4 = 0;
			var numbits = NumBits;

			foreach (var num3 in Value)
			{
				var num5 = 0x80;
				var num = (numbits < 8) ? numbits : 8;

				for (var j = 0; j < num; ++j)
				{
					flagArray[num4++] = (num3 & num5) != 0;
					num5 = num5 >> 1;
				}

				numbits -= 8;
			}

			return flagArray;
		}

		public virtual string ToHexString()
		{
			var str = new StringBuilder("").ToString();

			foreach (var b in Value)
			{
				str = str + Asn1Util.ToHexString(b);
			}

			return str;
		}

		public override string ToString()
		{
			var str = new StringBuilder("").ToString();

			if (NumBits <= 0x10)
			{
				if (NumBits != 0)
				{
					var flagArray = ToBoolArray();

					foreach (bool b in flagArray)
					{
						str = str + (b ? "1" : "0");
					}
				}

				return str;
			}

			var num2 = 4;
			var capacity = (NumBits + 3) / 4;
			var builder = new StringBuilder(capacity);

			if (Value != null)
			{
				var num4 = 0;
				var index = 0;

				while (num4 < capacity)
				{
					var num6 = (Value[index] >> num2) & 15;
					builder.Append((char)(num6 + ((num6 >= 10) ? 0x57 : 0x30)));
					num2 -= 4;

					if (num2 < 0)
					{
						num2 = 4;
						index++;
					}

					num4++;
				}
			}

			return builder.ToString();
		}

		public virtual bool this[int bitIndex]
		{
			get { return Get(bitIndex); }
			set { Set(bitIndex, value); }
		}

		public override int Length
		{
			get { return NumBits; }
		}
	}
}