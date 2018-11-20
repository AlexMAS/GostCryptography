using System;
using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public abstract class Asn1EncodeBuffer : Asn1MessageBuffer
	{
		public const int DefaultSizeIncrement = 0x400;

		protected byte[] Data;
		protected int ByteIndex;
		protected int SizeIncrement;

		protected Asn1EncodeBuffer()
		{
			InitBuffer(DefaultSizeIncrement);
		}

		protected Asn1EncodeBuffer(int sizeIncrement)
		{
			if (sizeIncrement == 0)
			{
				sizeIncrement = DefaultSizeIncrement;
			}

			InitBuffer(sizeIncrement);
		}

		public abstract byte[] MsgCopy { get; }

		public abstract int MsgLength { get; }

		public virtual void BinDump(string varName)
		{
			var outs = new StreamWriter(Console.OpenStandardOutput(), Console.Out.Encoding)
					   {
						   AutoFlush = true
					   };

			BinDump(outs, varName);
		}

		public abstract void BinDump(StreamWriter outs, string varName);

		protected internal virtual void CheckSize(int bytesRequired)
		{
			if ((ByteIndex + bytesRequired) > Data.Length)
			{
				var num = ((bytesRequired - 1) / SizeIncrement) + 1;
				var num2 = num * SizeIncrement;
				var destinationArray = new byte[Data.Length + num2];

				Array.Copy(Data, 0, destinationArray, 0, ByteIndex + 1);

				Data = destinationArray;
			}
		}

		public abstract void Copy(byte value);

		public abstract void Copy(byte[] value);

		public virtual void HexDump()
		{
			HexDump(GetInputStream());
		}

		public virtual void HexDump(StreamWriter outs)
		{
			HexDump(GetInputStream(), outs);
		}

		protected virtual void InitBuffer(int sizeIncrement)
		{
			SizeIncrement = sizeIncrement;
			Data = new byte[SizeIncrement];
			ByteIndex = 0;
		}

		public abstract void Reset();

		public abstract void Write(Stream outs);
	}
}