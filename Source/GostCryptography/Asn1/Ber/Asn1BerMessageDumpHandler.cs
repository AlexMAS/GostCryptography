using System;
using System.IO;
using System.Text;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1BerMessageDumpHandler : IAsn1TaggedEventHandler
	{
		private const int MaxBytesPerLine = 12;

		private int _offset;
		private readonly StreamWriter _printStream;

		public Asn1BerMessageDumpHandler()
		{
			_printStream = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
			_offset = 0;
		}

		public Asn1BerMessageDumpHandler(StreamWriter outs)
		{
			_printStream = outs;
			_offset = 0;
		}

		public virtual void Contents(byte[] data)
		{
			if (data.Length != 0)
			{
				PrintOffset();

				var flag = true;
				var builder = new StringBuilder(100);
				var builder2 = new StringBuilder(100);

				for (var i = 0; i < data.Length; ++i)
				{
					builder.Append(Asn1Util.ToHexString(data[i]));
					builder.Append(' ');

					int num2 = data[i];

					if ((num2 >= 0x20) && (num2 <= 0x7f))
					{
						builder2.Append((char)num2);
					}
					else
					{
						builder2.Append('.');
					}

					if (((i + 1) % MaxBytesPerLine) == 0)
					{
						if (!flag)
						{
							_printStream.Write("     : ");
						}
						else
						{
							flag = false;
						}

						_printStream.WriteLine(builder + ": " + builder2);

						builder.Length = 0;
						builder2.Length = 0;
					}
				}

				if (builder.Length > 0)
				{
					while (builder.Length < 0x24)
					{
						builder.Append(' ');
					}

					if (!flag)
					{
						_printStream.Write("     : ");
					}

					_printStream.WriteLine(builder + ": " + builder2);
				}

				_offset += data.Length;
			}
		}

		public virtual void EndElement(Asn1Tag tag)
		{
		}

		public virtual void StartElement(Asn1Tag tag, int len, byte[] tagLenBytes)
		{
			PrintOffset();

			new StringBuilder(40); // WTF?

			var index = 0;

			while (index < tagLenBytes.Length)
			{
				_printStream.Write(Asn1Util.ToHexString(tagLenBytes[index]));
				_printStream.Write(' ');
				index++;
			}

			while (index < MaxBytesPerLine)
			{
				_printStream.Write("   ");
				index++;
			}

			_printStream.Write(": ");
			_printStream.Write(tag.Constructed ? "C " : "P ");
			_printStream.Write(tag + " ");
			_printStream.WriteLine(Convert.ToString(len));
			_offset += tagLenBytes.Length;
		}

		private void PrintOffset()
		{
			var str = Convert.ToString(_offset);
			var num = 4 - str.Length;

			for (var i = 0; i < num; ++i)
			{
				_printStream.Write('0');
			}

			_printStream.Write(str);
			_printStream.Write(" : ");
		}
	}
}