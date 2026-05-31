#include "scim_query.h"

#include "utils.h"

bool parse_scim_list_query_params(const char *start_index_param,
                                  const char *count_param,
                                  const char *filter_param,
                                  ScimListQuery &query,
                                  std::string &error_message) {
  if (auto parsed_start = parse_int_param(start_index_param)) {
    query.startIndex = *parsed_start;
  }
  if (auto parsed_count = parse_int_param(count_param)) {
    query.count = *parsed_count;
  }
  if (filter_param) {
    query.filter = trim_copy(filter_param);
  }

  if (query.startIndex <= 0) {
    error_message = "startIndex must be >= 1";
    return false;
  }
  if (query.count < 0) {
    error_message = "count must be >= 0";
    return false;
  }
  if (query.count > 200) query.count = 200;
  return true;
}

ScimPageWindow scim_page_window(const ScimListQuery &query,
                                std::size_t total_results) {
  std::size_t start_offset = 0;
  if (query.startIndex > 1) {
    start_offset = static_cast<std::size_t>(query.startIndex) - 1;
  }
  if (start_offset > total_results) start_offset = total_results;

  std::size_t count = 0;
  if (query.count > 0) count = static_cast<std::size_t>(query.count);
  const std::size_t remaining = total_results - start_offset;
  if (count > remaining) count = remaining;

  return {start_offset, start_offset + count};
}

std::optional<ScimFilterExpression> parse_scim_filter_expression(
    const std::string &raw_filter, std::string &error_message) {
  const std::string filter = trim_copy(raw_filter);
  if (filter.empty()) return std::nullopt;

  const size_t first_space = filter.find(' ');
  if (first_space == std::string::npos) {
    error_message = "Invalid SCIM filter format";
    return std::nullopt;
  }
  const size_t second_space = filter.find(' ', first_space + 1);
  if (second_space == std::string::npos) {
    error_message = "Invalid SCIM filter format";
    return std::nullopt;
  }

  ScimFilterExpression expression;
  expression.attribute = to_lower(trim_copy(filter.substr(0, first_space)));
  expression.op =
      to_lower(trim_copy(filter.substr(first_space + 1,
                                       second_space - first_space - 1)));
  expression.value = trim_copy(filter.substr(second_space + 1));

  if (expression.attribute.empty() || expression.value.empty()) {
    error_message = "SCIM filter attribute and value are required";
    return std::nullopt;
  }
  if (expression.value.size() >= 2 &&
      ((expression.value.front() == '"' && expression.value.back() == '"') ||
       (expression.value.front() == '\'' && expression.value.back() == '\''))) {
    expression.value = expression.value.substr(1, expression.value.size() - 2);
  }

  if (!is_allowed_role(expression.op, {"eq", "co", "sw"})) {
    error_message = "Unsupported SCIM filter operator: " + expression.op;
    return std::nullopt;
  }
  if (expression.value.empty()) {
    error_message = "SCIM filter value cannot be empty";
    return std::nullopt;
  }

  return expression;
}

bool scim_match_string_expr(const std::string &raw,
                            const ScimFilterExpression &expression) {
  const std::string actual = to_lower(raw);
  const std::string expected = to_lower(expression.value);
  if (expression.op == "eq") return actual == expected;
  if (expression.op == "co") return actual.find(expected) != std::string::npos;
  if (expression.op == "sw") return actual.rfind(expected, 0) == 0;
  return false;
}

bool scim_user_filter_supported_attribute(const std::string &attribute) {
  return is_allowed_role(attribute,
                         {"id", "username", "user.name", "displayname",
                          "role", "roles", "active"});
}

bool scim_group_filter_supported_attribute(const std::string &attribute) {
  return is_allowed_role(attribute,
                         {"id", "displayname", "members", "member"});
}
