#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/catalog/catalog_entry/scalar_function_catalog_entry.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/function/function_serialization.hpp"
#include "duckdb/common/serializer/format_serializer.hpp"
#include "duckdb/common/serializer/format_deserializer.hpp"

namespace duckdb {

BoundFunctionExpression::BoundFunctionExpression(LogicalType return_type, ScalarFunction bound_function,
                                                 vector<unique_ptr<Expression>> arguments,
                                                 unique_ptr<FunctionData> bind_info, bool is_operator)
    : Expression(ExpressionType::BOUND_FUNCTION, ExpressionClass::BOUND_FUNCTION, std::move(return_type)),
      function(std::move(bound_function)), children(std::move(arguments)), bind_info(std::move(bind_info)),
      is_operator(is_operator) {
	D_ASSERT(!function.name.empty());
}

bool BoundFunctionExpression::HasSideEffects() const {
	return function.side_effects == FunctionSideEffects::HAS_SIDE_EFFECTS ? true : Expression::HasSideEffects();
}

bool BoundFunctionExpression::IsFoldable() const {
	// functions with side effects cannot be folded: they have to be executed once for every row
	return function.side_effects == FunctionSideEffects::HAS_SIDE_EFFECTS ? false : Expression::IsFoldable();
}

string BoundFunctionExpression::ToString() const {
	return FunctionExpression::ToString<BoundFunctionExpression, Expression>(*this, string(), function.name,
	                                                                         is_operator);
}
bool BoundFunctionExpression::PropagatesNullValues() const {
	return function.null_handling == FunctionNullHandling::SPECIAL_HANDLING ? false
	                                                                        : Expression::PropagatesNullValues();
}

hash_t BoundFunctionExpression::Hash() const {
	hash_t result = Expression::Hash();
	return CombineHash(result, function.Hash());
}

bool BoundFunctionExpression::Equals(const BaseExpression &other_p) const {
	if (!Expression::Equals(other_p)) {
		return false;
	}
	auto &other = other_p.Cast<BoundFunctionExpression>();
	if (other.function != function) {
		return false;
	}
	if (!Expression::ListEquals(children, other.children)) {
		return false;
	}
	if (!FunctionData::Equals(bind_info.get(), other.bind_info.get())) {
		return false;
	}
	return true;
}

unique_ptr<Expression> BoundFunctionExpression::Copy() {
	vector<unique_ptr<Expression>> new_children;
	new_children.reserve(children.size());
	for (auto &child : children) {
		new_children.push_back(child->Copy());
	}
	unique_ptr<FunctionData> new_bind_info = bind_info ? bind_info->Copy() : nullptr;

	auto copy = make_uniq<BoundFunctionExpression>(return_type, function, std::move(new_children),
	                                               std::move(new_bind_info), is_operator);
	copy->CopyProperties(*this);
	return std::move(copy);
}

void BoundFunctionExpression::Verify() const {
	D_ASSERT(!function.name.empty());
}

void BoundFunctionExpression::Serialize(FieldWriter &writer) const {
	D_ASSERT(!function.name.empty());
	D_ASSERT(return_type == function.return_type);
	writer.WriteField(is_operator);
	FunctionSerializer::Serialize<ScalarFunction>(writer, function, return_type, children, bind_info.get());
}

unique_ptr<Expression> BoundFunctionExpression::Deserialize(ExpressionDeserializationState &state,
                                                            FieldReader &reader) {
	auto is_operator = reader.ReadRequired<bool>();
	vector<unique_ptr<Expression>> children;
	unique_ptr<FunctionData> bind_info;
	auto function = FunctionSerializer::Deserialize<ScalarFunction, ScalarFunctionCatalogEntry>(
	    reader, state, CatalogType::SCALAR_FUNCTION_ENTRY, children, bind_info);

	auto return_type = function.return_type;
	return make_uniq<BoundFunctionExpression>(std::move(return_type), std::move(function), std::move(children),
	                                          std::move(bind_info), is_operator);
}

void BoundFunctionExpression::FormatSerialize(FormatSerializer &serializer) const {
	Expression::FormatSerialize(serializer);
	serializer.WriteProperty("return_type", return_type);
	serializer.WriteProperty("children", children);
	FunctionSerializer::FormatSerialize(serializer, function, bind_info.get());
	serializer.WriteProperty("is_operator", is_operator);
}

unique_ptr<Expression> BoundFunctionExpression::FormatDeserialize(FormatDeserializer &deserializer) {
	auto return_type = deserializer.ReadProperty<LogicalType>("return_type");
	auto children = deserializer.ReadProperty<vector<unique_ptr<Expression>>>("children");
	auto entry = FunctionSerializer::FormatDeserialize<ScalarFunction, ScalarFunctionCatalogEntry>(
	    deserializer, CatalogType::SCALAR_FUNCTION_ENTRY, children);
	auto result = make_uniq<BoundFunctionExpression>(std::move(return_type), std::move(entry.first),
	                                                 std::move(children), std::move(entry.second));
	deserializer.ReadProperty("is_operator", result->is_operator);
	return std::move(result);
}

} // namespace duckdb
