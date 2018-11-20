using System;
using System.Text;

using GostCryptography.Properties;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn1Time : Asn18BitCharString, IComparable
	{
		public const int January = 1;
		public const int February = 2;
		public const int March = 3;
		public const int April = 4;
		public const int May = 5;
		public const int June = 6;
		public const int July = 7;
		public const int August = 8;
		public const int September = 9;
		public const int October = 10;
		public const int November = 11;
		public const int December = 12;

		public static readonly short[] DaysInMonth = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };


		public Asn1Time(short typeCode, bool useDerRules)
			: base(typeCode)
		{
			DerRules = useDerRules;
			Init();
		}

		public Asn1Time(string data, short typeCode, bool useDerRules)
			: base(data, typeCode)
		{
			DerRules = useDerRules;
			Init();
		}


		[NonSerialized]
		protected bool Parsed;

		[NonSerialized]
		protected bool DerRules;


		[NonSerialized]
		protected int DiffHourValue;

		public virtual int DiffHour
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return DiffHourValue;
			}
			set
			{
				if ((value < -12) || (value > 12))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidDiffHourValue, value);
				}

				SafeParseString();
				DiffHourValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int DiffMinValue;

		public virtual int DiffMinute
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}

				return DiffMinValue;
			}
		}


		[NonSerialized]
		protected string SecFraction;

		public virtual string Fraction
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return SecFraction;
			}
			set
			{
				SafeParseString();
				SecFraction = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int YearValue;

		public virtual int Year
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return YearValue;
			}
			set
			{
				if (value < 0)
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidYearValue, value);
				}

				if (!CheckDate(DayValue, MonthValue, value))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidYearValueForDayAndMonth, value, DayValue, MonthValue);
				}

				SafeParseString();
				YearValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int MonthValue;

		public virtual int Month
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}

				return MonthValue;
			}
			set
			{
				if ((value < 1) || (value > 12))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidMonthValue, value);
				}

				if (!CheckDate(DayValue, value, YearValue))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidMonthValueForDayAndYear, value, DayValue, YearValue);
				}

				SafeParseString();
				MonthValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int DayValue;

		public virtual int Day
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return DayValue;
			}
			set
			{
				if (((value < 1) || (value > 31)) || !CheckDate(value, MonthValue, YearValue))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidDayValueForMonthAndYear, value, MonthValue, YearValue);
				}

				SafeParseString();
				DayValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int HourValue;

		public virtual int Hour
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return HourValue;
			}
			set
			{
				if ((value < 0) || (value > 23))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidHourValue, value);
				}

				SafeParseString();
				HourValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int MinuteValue;

		public virtual int Minute
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return MinuteValue;
			}
			set
			{
				if ((value < 0) || (value > 59))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidMinuteValue, value);
				}

				SafeParseString();
				MinuteValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected int SecondValue;

		public virtual int Second
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
				return SecondValue;
			}
			set
			{
				if ((value < 0) || (value > 59))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidSecondValue, value);
				}

				SafeParseString();
				SecondValue = value;
				CompileString();
			}
		}


		[NonSerialized]
		protected bool UtcFlag;

		public virtual bool Utc
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}

				return UtcFlag;
			}
			set
			{
				if (!DerRules)
				{
					SafeParseString();
					UtcFlag = value;
					CompileString();
				}
			}
		}


		public virtual int CompareTo(object other)
		{
			if (other is DateTime)
			{
				var time2 = (DateTime)other;
				return (int)(GetTime().Ticks - time2.Ticks);
			}
			return (int)(GetTime().Ticks - ((Asn1Time)other).GetTime().Ticks);
		}


		protected static char CharAt(string s, int index)
		{
			if (index >= s.Length)
			{
				return '\0';
			}

			return s[index];
		}

		private static bool CheckDate(int day, int month, int year)
		{
			if ((day <= 0) || (month <= 0))
			{
				return true;
			}

			if ((year >= 0) && (month > 0))
			{
				int num = DaysInMonth[month];

				if (((month == 2) && ((year % 4) == 0)) && (((year % 100) != 0) || ((year % 400) == 0)))
				{
					num++;
				}

				if ((day >= 1) && (day <= num))
				{
					return true;
				}
			}
			else if (month > 0)
			{
				if (day <= DaysInMonth[month])
				{
					return true;
				}

				if ((month == 2) && (day <= (DaysInMonth[month] + 1)))
				{
					return true;
				}
			}

			return false;
		}

		public virtual void Clear()
		{
			YearValue = MonthValue = DayValue = HourValue = -1;
			MinuteValue = SecondValue = DiffHourValue = DiffMinValue = 0;
			UtcFlag = DerRules;
			Parsed = true;
			SecFraction = "";
			Value = "";
		}

		protected abstract bool CompileString();

		protected override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength, Asn1Tag tag)
		{
			Parsed = false;
			base.Decode(buffer, explicitTagging, implicitLength, tag);
			DerRules = buffer is Asn1DerDecodeBuffer;
		}

		protected override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging, Asn1Tag tag)
		{
			SafeParseString();

			var flag = buffer is Asn1DerEncodeBuffer;

			if (DerRules != flag)
			{
				DerRules = flag;

				if (!CompileString())
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1TimeStringCouldNotBeGenerated);
				}
			}

			return base.Encode(buffer, explicitTagging, tag);
		}

		public virtual void Encode(Asn1BerOutputStream outs, bool explicitTagging, Asn1Tag tag)
		{
			SafeParseString();
			outs.EncodeCharString(Value, explicitTagging, tag);
		}

		public override bool Equals(object value)
		{
			if (value is Asn1Time)
			{
				return GetTime().Equals(((Asn1Time)value).GetTime());
			}

			return ((value is DateTime) && GetTime().Equals((DateTime)value));
		}

		public virtual int GetDiff()
		{
			if (!Parsed)
			{
				ParseString(Value);
			}

			return ((DiffHourValue * 60) + DiffMinValue);
		}

		public override int GetHashCode()
		{
			return Value.GetHashCode();
		}

		public virtual DateTime GetTime()
		{
			if (!string.IsNullOrEmpty(SecFraction))
			{
				return new DateTime(YearValue, MonthValue, DayValue, HourValue, MinuteValue, SecondValue, int.Parse(SecFraction));
			}

			return new DateTime(YearValue, MonthValue, DayValue, HourValue, MinuteValue, SecondValue);
		}

		protected virtual void Init()
		{
			YearValue = MonthValue = DayValue = HourValue = -1;
			MinuteValue = SecondValue = 0;
			DiffHourValue = DiffMinValue = 0;
			UtcFlag = DerRules;
			SecFraction = "";
		}

		protected static int ParseInt(string str, IntHolder off, int len)
		{
			if ((off.Value + len) > str.Length)
			{
				throw ExceptionUtility.ArgumentOutOfRange("off");
			}

			var mValue = off.Value;
			off.Value += len;

			return int.Parse(str.Substring(mValue, len));
		}

		public abstract void ParseString(string data);

		protected virtual void PutInteger(int width, int value)
		{
			PutInteger(StringBuffer, width, value);
		}

		public static void PutInteger(StringBuilder data, int width, int value)
		{
			var str = Convert.ToString(value);
			var length = str.Length;

			if (length < width)
			{
				for (var i = length; i < width; i++)
				{
					data.Append('0');
				}
			}
			else if (length > width)
			{
				str = str.Substring(length - width);
			}

			data.Append(str);
		}

		protected virtual void SafeParseString()
		{
			try
			{
				if (!Parsed)
				{
					ParseString(Value);
				}
			}
			catch (Exception)
			{
			}
		}

		public virtual void SetDiff(int inMinutes)
		{
			if (Math.Abs(inMinutes) > 720)
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidDiffValue, inMinutes);
			}

			SafeParseString();
			DiffHourValue = inMinutes / 60;
			DiffMinValue = inMinutes % 60;
			CompileString();
		}

		public virtual void SetDiff(int dhour, int dminute)
		{
			if ((dhour < -12) || (dhour > 12))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidDiffHourValue, dhour);
			}

			if (Math.Abs(dminute) > 59)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1InvalidDiffMinuteValue, dminute);
			}

			SafeParseString();
			DiffHourValue = dhour;

			if (dhour < 0)
			{
				DiffMinValue = -Math.Abs(dminute);
			}
			else
			{
				DiffMinValue = Math.Abs(dminute);
			}

			CompileString();
		}

		public virtual void SetTime(DateTime time)
		{
			Clear();
			YearValue = time.Year;
			MonthValue = time.Month;
			DayValue = time.Day;
			HourValue = time.Hour;
			MinuteValue = time.Minute;
			SecondValue = time.Second;
			SecFraction = Convert.ToString(time.Millisecond);
			DiffHourValue = DiffMinValue = 0;
			UtcFlag = DerRules;
			CompileString();
		}
	}
}