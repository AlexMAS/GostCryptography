using System;
using System.IO;

namespace GostCryptography.Asn1.Ber
{
	public class Asn1TraceHandler : IAsn1NamedEventHandler
	{
		internal StreamWriter mPrintStream;

		public Asn1TraceHandler()
		{
			mPrintStream = new StreamWriter(Console.OpenStandardOutput(), Console.Out.Encoding);
			mPrintStream.AutoFlush = true;
		}

		public Asn1TraceHandler(StreamWriter ps)
		{
			mPrintStream = ps;
		}

		public virtual void Characters(string svalue, short typeCode)
		{
			mPrintStream.WriteLine("data: " + svalue);
		}

		public virtual void EndElement(string name, int index)
		{
			mPrintStream.Write(name);
			if (index >= 0)
			{
				mPrintStream.Write("[" + index + "]");
			}
			mPrintStream.WriteLine(": end");
		}

		public virtual void StartElement(string name, int index)
		{
			mPrintStream.Write(name);
			if (index >= 0)
			{
				mPrintStream.Write("[" + index + "]");
			}
			mPrintStream.WriteLine(": start");
		}
	}
}