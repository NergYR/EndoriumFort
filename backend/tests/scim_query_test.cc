#include "scim_query.h"

#include <iostream>
#include <string>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

}  // namespace

int main() {
  bool ok = true;

  {
    ScimListQuery query;
    std::string error;
    ok &= expect(parse_scim_list_query_params(nullptr, nullptr, nullptr, query,
                                              error),
                 "default SCIM query params should be accepted");
    ok &= expect(query.startIndex == 1,
                 "default startIndex should remain 1");
    ok &= expect(query.count == 100, "default count should remain 100");
    ok &= expect(query.filter.empty(), "default filter should stay empty");
  }

  {
    ScimListQuery query;
    std::string error;
    ok &= expect(parse_scim_list_query_params("3", "20", " userName co \"admin\" ",
                                              query, error),
                 "explicit SCIM query params should be accepted");
    ok &= expect(query.startIndex == 3,
                 "startIndex should parse from query params");
    ok &= expect(query.count == 20, "count should parse from query params");
    ok &= expect(query.filter == "userName co \"admin\"",
                 "filter should be trimmed");
  }

  {
    ScimListQuery query;
    std::string error;
    ok &= expect(!parse_scim_list_query_params("0", "20", nullptr, query,
                                               error),
                 "startIndex=0 should be rejected");
    ok &= expect(error == "startIndex must be >= 1",
                 "startIndex validation message should be explicit");
  }

  {
    ScimListQuery query;
    std::string error;
    ok &= expect(!parse_scim_list_query_params("1", "-1", nullptr, query,
                                               error),
                 "negative count should be rejected");
    ok &= expect(error == "count must be >= 0",
                 "count validation message should be explicit");
  }

  {
    ScimListQuery query;
    std::string error;
    ok &= expect(parse_scim_list_query_params("2", "999", nullptr, query,
                                              error),
                 "large count should be accepted then clamped");
    ok &= expect(query.count == 200,
                 "count should be clamped to SCIM maxResults=200");
  }

  {
    ScimListQuery query;
    std::string error;
    ok &= expect(parse_scim_list_query_params("NaN", "x", nullptr, query,
                                              error),
                 "non-numeric params should fall back to defaults");
    ok &= expect(query.startIndex == 1,
                 "invalid startIndex should keep default value");
    ok &= expect(query.count == 100,
                 "invalid count should keep default value");
  }

  {
    std::string error;
    auto expression =
        parse_scim_filter_expression("userName co \"Admin\"", error);
    ok &= expect(expression.has_value(),
                 "valid SCIM filter should parse successfully");
    if (expression) {
      ok &= expect(expression->attribute == "username",
                   "filter attribute should normalize to lowercase");
      ok &= expect(expression->op == "co",
                   "filter operator should normalize to lowercase");
      ok &= expect(expression->value == "Admin",
                   "quoted filter value should be unwrapped");
      ok &= expect(scim_match_string_expr("SYSTEM-ADMIN", *expression),
                   "contains operator should be case-insensitive");
    }
  }

  {
    std::string error;
    auto expression = parse_scim_filter_expression("displayName sw 'Ops'", error);
    ok &= expect(expression.has_value(),
                 "single-quoted SCIM filter should parse successfully");
    if (expression) {
      ok &= expect(expression->value == "Ops",
                   "single-quoted filter value should be unwrapped");
      ok &= expect(scim_match_string_expr("ops-team", *expression),
                   "starts-with operator should be case-insensitive");
    }
  }

  {
    std::string error;
    auto expression = parse_scim_filter_expression("role neq admin", error);
    ok &= expect(!expression.has_value(),
                 "unsupported SCIM operator should be rejected");
    ok &= expect(error == "Unsupported SCIM filter operator: neq",
                 "unsupported operator should return explicit error");
  }

  {
    std::string error;
    auto expression = parse_scim_filter_expression("invalidfilter", error);
    ok &= expect(!expression.has_value(),
                 "malformed SCIM filter should be rejected");
    ok &= expect(error == "Invalid SCIM filter format",
                 "invalid format should return explicit error");
  }

  {
    std::string error;
    auto expression = parse_scim_filter_expression("userName eq \"\"", error);
    ok &= expect(!expression.has_value(),
                 "empty SCIM filter value should be rejected");
    ok &= expect(error == "SCIM filter value cannot be empty",
                 "empty value should return explicit error");
  }

  {
    std::string error;
    ok &= expect(scim_user_filter_supported_attribute("id"),
                 "SCIM users filter should support id");
    ok &= expect(scim_user_filter_supported_attribute("roles"),
                 "SCIM users filter should support roles");
    ok &= expect(!scim_user_filter_supported_attribute("emails"),
                 "SCIM users filter should reject unsupported attribute");
    ok &= expect(scim_group_filter_supported_attribute("members"),
                 "SCIM groups filter should support members");
    ok &= expect(!scim_group_filter_supported_attribute("externalid"),
                 "SCIM groups filter should reject unsupported attribute");

    ScimFilterExpression eq_expr{"username", "eq", "Alice"};
    ok &= expect(scim_match_string_expr("alice", eq_expr),
                 "eq operator should be case-insensitive");
  }

  if (!ok) {
    return 1;
  }

  std::cout << "All SCIM query tests passed." << std::endl;
  return 0;
}
