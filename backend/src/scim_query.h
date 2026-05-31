#pragma once

#include <cstddef>
#include <optional>
#include <string>

struct ScimListQuery {
  int startIndex = 1;
  int count = 100;
  std::string filter;
};

struct ScimFilterExpression {
  std::string attribute;
  std::string op;
  std::string value;
};

struct ScimPageWindow {
  std::size_t start = 0;
  std::size_t end = 0;
};

bool parse_scim_list_query_params(const char *start_index_param,
                                  const char *count_param,
                                  const char *filter_param,
                                  ScimListQuery &query,
                                  std::string &error_message);

ScimPageWindow scim_page_window(const ScimListQuery &query,
                                std::size_t total_results);

std::optional<ScimFilterExpression> parse_scim_filter_expression(
    const std::string &raw_filter, std::string &error_message);

bool scim_match_string_expr(const std::string &raw,
                            const ScimFilterExpression &expression);

bool scim_user_filter_supported_attribute(const std::string &attribute);
bool scim_group_filter_supported_attribute(const std::string &attribute);
