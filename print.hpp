#pragma once

#include <format>
#include <cstdio>

template<class... Args>
void print(std::format_string<Args...> fmt, Args&&... args)
{
    auto str = std::vformat(fmt.get(), std::make_format_args(args...));
    printf("%s", str.c_str());
}
