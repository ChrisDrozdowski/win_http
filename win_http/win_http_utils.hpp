#ifndef WIN_HTTP_UTILS
#define WIN_HTTP_UTILS

#include <iomanip>
#include <string>
#include <sstream>
#include <unordered_map>
#include <windows.h>


namespace win_http::headers {

	// CaseInsensitiveMultimap and parse() adapted from Simple-Web-Server
	// Copyright (c) 2014-2020 Ole Christian Eidheim, MIT-licensed.

	inline bool case_insensitive_equal(const std::string& str1, const std::string& str2) noexcept {
		return str1.size() == str2.size() &&
			std::equal(str1.begin(), str1.end(), str2.begin(), [](wchar_t a, wchar_t b) {
			return tolower(a) == tolower(b);
				});
	}
	class CaseInsensitiveEqual {
	public:
		bool operator()(const std::string& str1, const std::string& str2) const noexcept {
			return case_insensitive_equal(str1, str2);
		}
	};
	class CaseInsensitiveHash {
	public:
		std::size_t operator()(const std::string& str) const noexcept {
			std::size_t h = 0;
			std::hash<int> hash;
			for (auto c : str)
				h ^= hash(tolower(c)) + 0x9e3779b9 + (h << 6) + (h >> 2);
			return h;
		}
	};
	using CaseInsensitiveMultimap = std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;

	// Implementation of CaseInsensitiveMultimap to handle HTTP headers.
	using headers_map = CaseInsensitiveMultimap;

	headers_map parse(std::istream& stream) {
		headers_map result;
		std::string line;
		std::size_t param_end;
		while (getline(stream, line) && (param_end = line.find(':')) != std::string::npos) {
			std::size_t value_start = param_end + 1;
			while (value_start + 1 < line.size() && line[value_start] == ' ')
				++value_start;
			if (value_start < line.size())
				result.emplace(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - (line.back() == L'\r' ? 1 : 0)));
		}
		return result;
	}

	headers_map from_string(const std::string& str) {
		std::stringstream ss(str);
		return parse(ss);
	}

	std::string to_string(const headers_map& hm) {
		std::stringstream ss;
		for (const std::pair<std::string, std::string>& h : hm) {
			ss << h.first << ":" << h.second << "\r\n";
		}
		std::string str = ss.str();
		return str.erase(str.find_last_not_of("\r\n") + 1); // Remove trailing \r\n.
	}

} // End namespace


namespace win_http::utils {

	inline std::wstring to_wide(const std::string& str) {
		if (str.empty())
			return std::wstring();
		int len = ::MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
		if (len < 1)
			return std::wstring();
		std::wstring wstr(len, '\0');
		if (0 == ::MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], static_cast<int>(wstr.size())))
			return std::wstring();
		return wstr;
	}

	inline std::string from_wide(const std::wstring& wstr) {
		if (wstr.empty())
			return std::string();
		int len = ::WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
		if (len < 1)
			return std::string();
		std::string str(len, '\0');
		if (0 == ::WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], static_cast<int>(str.size()), NULL, NULL))
			return std::string();
		return str;
	}

	std::string get_http_time(const SYSTEMTIME& st) {
		const std::vector<std::string> days = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
		const std::vector<std::string> months = { ""/*Need blank*/, "Jan", "Feb", "Mar", "Apr", "May",
			"Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
		// Mon, 15 Nov, 1994 12:45:26 GMT;
		std::ostringstream ss;
		ss << days[st.wDayOfWeek] << ", ";
		ss << std::setw(2) << std::setfill('0') << st.wDay << " ";
		ss << months[st.wMonth] << L", ";
		ss << st.wYear << L" ";
		ss << std::setw(2) << std::setfill('0') << st.wHour << ":";
		ss << std::setw(2) << std::setfill('0') << st.wMinute << ":";
		ss << std::setw(2) << std::setfill('0') << st.wSecond << " GMT";
		return ss.str();
	}

	std::string get_http_time() {
		SYSTEMTIME st;
		::GetSystemTime(&st);
		return get_http_time(st);
	}

	std::vector<char> to_char_vector(const std::string& str) {
		return std::vector<char>(str.begin(), str.end());
	}

	std::string from_char_vector(const std::vector<char>& vec) {
		return std::string(vec.begin(), vec.end());
	}

} // End namespace

#endif /*WIN_HTTP_UTILS */