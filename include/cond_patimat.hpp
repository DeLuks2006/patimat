#include "patimat.hpp"
#include <print>

namespace patimat {
    class cc_pattern_matcher : public pattern_matcher {
        private:

            static uint8_t hex_str_to_val(std::string_view sv) {
                uint8_t val = 0;
                std::from_chars(sv.data(), sv.data() + sv.size(), val, 16);
                return val;
            }

            struct CondOperand {
                bool is_prev;
                bool is_idx;
                uint8_t val;
                uint8_t idx;
    
                uint8_t resolve(std::span<uint8_t> m) const {
                    return is_idx ? m[idx] : val;
                }
    
                static CondOperand parse(std::string_view token) {
                    if (token.starts_with('[') && token.ends_with(']')) {
                        return { false, true, 0, hex_str_to_val(token.substr(1, token.size() - 2)) };
                    }
                    return {false, false, hex_str_to_val(token), 0};
                }
            };

            struct CondToken {
                enum class Op { Eq, Neq, Xor, And, Or, Add, Sub };
                CondOperand lhs;
                CondOperand rhs;
                Op op;

                uint8_t eval(std::span<uint8_t> m, uint8_t acc = 0) const {
                    uint8_t l = lhs.is_prev ? acc : lhs.resolve(m);
                    uint8_t r = rhs.resolve(m);
                    switch (op) {
                        case Op::Eq:
                            return l == r;
                        case Op::Neq: 
                            return l != r;
                        case Op::Xor:
                            return l ^ r;
                        case Op::And: 
                            return l & r;
                        case Op::Or: 
                            return l | r;
                        case Op::Add:
                            return l + r;
                        case Op::Sub:
                            return l - r;
                    }
                    return 0;
                }
            };

            std::vector<std::vector<CondToken>> _conditions;

            bool check_conditions(std::span<uint8_t> m) const {
                for (const auto& group : _conditions) {
                    uint8_t acc = 0;
                    for (const auto& cond : group) {
                        if (cond.lhs.is_prev)
                            acc = cond.eval(m, acc);
                        else
                            acc = cond.eval(m);
                    }
                    if (!acc) return false;
                }
                return true;
            }

            std::vector<CondToken> parse_chain(std::string_view expr) {
                std::vector<CondToken> tokens;
                bool prev = false;
    
                auto parse_op = [](char c) -> CondToken::Op {
                    switch (c) {
                        case '=': return CondToken::Op::Eq;
                        case '!': return CondToken::Op::Neq;
                        case '^': return CondToken::Op::Xor;
                        case '&': return CondToken::Op::And;
                        case '|': return CondToken::Op::Or;
                        case '+': return CondToken::Op::Add;
                        case '-': return CondToken::Op::Sub;
                        default: throw std::invalid_argument("Invalid operator");
                    }
                };
                const std::string operators = "|^&=!+-";
                while (!expr.empty()) {
                    CondToken t;
                    t.lhs.is_prev = prev;
    
                    if (!prev) {
                        auto op_pos = expr.find_first_of(operators);
                        t.lhs = CondOperand::parse(expr.substr(0, op_pos));
                        expr = expr.substr(op_pos);
                    }
    
                    t.op = parse_op(expr[0]);
                    expr = expr.substr(expr[0] == '!' ? 2 : 1);
                    auto next = expr.find_first_of(operators);
                    t.rhs = CondOperand::parse(expr.substr(0, next));
                    expr = next == std::string_view::npos ? "" : expr.substr(next);
                    tokens.push_back(t);
                    prev = true;
                }
    
                return tokens;
            }

            std::vector<std::vector<CondToken>> parse_cond(std::string_view expr) {
                std::vector<std::vector<CondToken>> groups;
                const std::string and_operator = "and";
                while (!expr.empty()) {
                    auto next = expr.find(and_operator);
                    auto sub = next == std::string_view::npos 
                        ? expr 
                        : expr.substr(0, next);
                    while (!sub.empty() && sub.front() == ' ') 
                        sub.remove_prefix(1);
                    while (!sub.empty() && sub.back() == ' ') 
                        sub.remove_suffix(1);
                    groups.push_back(parse_chain(sub));
                    expr = next == std::string_view::npos ? "" : expr.substr(next + and_operator.size());
                }
                return groups;
            }
            
        public:
            using pattern_matcher::pattern_matcher;

            cc_pattern_matcher(std::string_view mat_pattern, std::string_view cond, std::string_view pat_pattern, std::span<uint8_t> memory)
                : pattern_matcher(mat_pattern, pat_pattern, memory)
            {
                set_conditions(cond);
            }

            cc_pattern_matcher(std::string_view mat_pattern, std::string_view cond, std::span<uint8_t> memory)
                : pattern_matcher(mat_pattern, memory)
            {
                set_conditions(cond);
            }
            
            void set_conditions(std::string_view conds) {
                _conditions = parse_cond(conds);
            }

            std::expected<uint8_t*, error> find_pattern() {
                if (_match_sig.empty())
                    return std::unexpected(error::invalid_signature);
                if (_memory.size() < _match_sig.size() || _memory.empty())
                    return std::unexpected(error::no_memory);
                if (_conditions.empty())
                    return std::unexpected(error::invalid_format);

                for (size_t i = 0; i <= _memory.size() - _match_sig.size(); ++i) {
                    bool match_found = true;
                    for (size_t j = 0; j < _match_sig.size(); ++j) {
                        if (!_match_sig[j].matches(_memory[i + j])) {
                            match_found = false;
                            break;
                        }
                    }
                    if (match_found) {
                        if (check_conditions(_memory.subspan(i, _match_sig.size()))) {
                            return &_memory[i];
                        }
                    }
                }
                
                return std::unexpected(error::not_found);
            }
            
            std::expected<std::vector<uint8_t*>, error> find_patterns() {
                if (_match_sig.empty())
                    return std::unexpected(error::invalid_signature);
                if (_memory.size() < _match_sig.size() || _memory.empty())
                    return std::unexpected(error::no_memory);
                if (_conditions.empty())
                    return std::unexpected(error::invalid_format);

                std::vector<uint8_t*> matches;

                size_t scan_end = _memory.size() - _match_sig.size();
                for (size_t i = 0; i <= scan_end; ++i) {
                    bool match_found = true;
                    for (size_t j = 0; j < _match_sig.size(); j++) {
                        if (!_match_sig[j].matches(_memory[i + j])) {
                            match_found = false;
                            break;
                        }
                    }
    
                    if (match_found) {
                        if (check_conditions(_memory.subspan(i, _match_sig.size()))) {
                            matches.push_back(&_memory[i]);
                            i += _match_sig.size() - 1;
                        }
                    }
                }

                if (matches.empty())
                    return std::unexpected(error::not_found);

                return matches;
            }
    };
}
