package io.nebulosus.predicates;


import com.hazelcast.query.Predicate;
import io.jsync.json.JsonArray;
import io.jsync.json.JsonElement;
import io.jsync.json.JsonObject;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JsonQueryPredicate implements Serializable, Predicate {

    final private JsonElement query;

    public JsonQueryPredicate(JsonElement query) {
        if(query == null){
            throw new NullPointerException("Your query cannot be null!");
        }
        this.query = query;
    }

    @Override
    public boolean apply(Map.Entry entry) {
        Object obj = entry.getValue();

        if(obj instanceof JsonObject && query.isObject()){
            return processJsonObjectQuery((JsonObject) obj, query.asObject());
        } else if(obj instanceof JsonObject && query.isArray()){
            for(Object q : query.asArray()){
                if(q instanceof JsonObject){
                    JsonObject jsonQuery = (JsonObject) q;
                    if(processJsonObjectQuery((JsonObject) obj, jsonQuery)){
                        return true;
                    }
                }
            }
        } else if(obj instanceof JsonArray){
            for(Object inObj : (JsonArray) obj){
                if(inObj instanceof JsonObject){
                    JsonObject jsonVal = (JsonObject) inObj;
                    if(query.isObject()){
                        if(processJsonObjectQuery(jsonVal, query.asObject())){
                            return true;
                        }
                    } else {
                        for(Object q : query.asArray()){
                            if(q instanceof JsonObject){
                                JsonObject jsonQuery = (JsonObject) q;
                                if(processJsonObjectQuery(jsonVal, jsonQuery)){
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean processJsonObjectQuery(JsonObject value, JsonObject query){

        if(query.size() == 0){
            return true;
        }

        if(query.size() > value.size()){
            return false;
        }

        JsonObject valueObj = value;

        boolean success = false;

        for(String field : query.getFieldNames()){

            Object queryValue = query.getValue(field);

            if(field.contains(".")){
                String[] subFields = field.split("\\.");
                JsonObject newValue = null;
                String newField = null;
                for(String sub : subFields){
                    if(newValue == null){
                        if(value.containsField(sub) && value.getValue(sub) instanceof JsonObject){
                            newValue = value.getObject(sub);
                            continue;
                        }
                        break;
                    }
                    newField = sub;
                    if(newValue.containsField(sub) && newValue.getValue(sub) instanceof JsonObject){
                        newValue = newValue.getObject(sub);
                    }
                }
                if(newValue != null && newField != null && field.endsWith("." + newField)){
                    valueObj = newValue;
                    field = newField;
                }
            }

            if(!valueObj.containsField(field)){
                return false;
            }

            Object value2 = valueObj.getValue(field);

            if(value2 instanceof JsonArray){
                JsonArray array = (JsonArray) value2;
                for(Object val : array.toArray()){
                    if(checkValue(queryValue, val)){
                        success = true;
                    }
                }
            } else {
                if(checkValue(queryValue, value2)){
                    success = true;
                } else {
                    return false;
                }
            }
        }

        return success;
    }

    private static boolean checkValue(Object queryVal, Object value2){
        if(queryVal.equals(value2)){
            return true;
        } else if(queryVal instanceof String && queryVal.toString().equals("*")){
            return true;
        } else if(queryVal instanceof String && queryVal.toString().matches("^v>\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split(">")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) > 0){
                return true;
            }
        } else if(queryVal instanceof String && queryVal.toString().matches("^v<\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split("<")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) < 0){
                return true;
            }
        } else if(queryVal instanceof String && queryVal.toString().matches("^v>=\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split(">=")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) >= 0){
                return true;
            }
        } else if(queryVal instanceof String && queryVal.toString().matches("^v<=\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split("<=")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) <= 0){
                return true;
            }
        } else if(queryVal instanceof String && queryVal.toString().matches("^v=\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split("=")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) == 0){
                return true;
            }
        } else if(queryVal instanceof String && queryVal.toString().matches("^v==\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split("==")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) == 0){
                return true;
            }
        } else if(queryVal instanceof String && queryVal.toString().matches("^v!=\\d+$") && value2 instanceof Number){
            Number numb1 = Long.parseLong(queryVal.toString().split("!=")[1]);
            Number numb2 = (Number) value2;
            if(compareTo(numb2, numb1) != 0){
                return true;
            }
        } else if(queryVal instanceof Boolean && value2 instanceof Boolean){
            if(queryVal == value2){
                return true;
            }
        } else if(queryVal instanceof String && value2 instanceof String){
            try {
                if(((String) queryVal).toLowerCase().equals(((String) value2).toLowerCase())){
                    return true;
                }
                Pattern p = Pattern.compile((String) queryVal);
                Matcher m = p.matcher((String) value2);
                if(m.matches()) {
                    return  true;
                } else if(m.find()){
                    return true;
                }
            } catch (Exception ignored){
            }
        } else if(queryVal instanceof JsonArray){
            JsonArray queryArray = (JsonArray) queryVal;
            for(Object qv : queryArray){
                if(checkValue(qv, value2)){
                    return true;
                }
            }
        } else if(queryVal instanceof JsonObject){
            JsonObject queryObj = (JsonObject) queryVal;
            boolean success = false;
            for(String newF : queryObj.getFieldNames()){
                Object obj = queryObj.getValue(newF);
                if(obj != null){
                    if(newF.equals("$exists") && obj instanceof Boolean){
                        success = (boolean) obj;
                    } else if(newF.equals("$eq")){
                        success = value2.equals(obj);
                    } else if(newF.equals("$gt") && obj instanceof Number && value2 instanceof Number){
                        success = checkValue("v>" + ((Number) obj).longValue(), value2);
                    } else if(newF.equals("$gte") && obj instanceof Number && value2 instanceof Number){
                        success = checkValue("v>=" + ((Number) obj).longValue(), value2);
                    } else if(newF.equals("$lt") && obj instanceof Number && value2 instanceof Number){
                        success = checkValue("v<" + ((Number) obj).longValue(), value2);
                    } else if(newF.equals("$lte") && obj instanceof Number && value2 instanceof Number){
                        success = checkValue("v<=" + ((Number) obj).longValue(), value2);
                    } else if(newF.equals("$ne") && obj instanceof Number && value2 instanceof Number){
                        success = checkValue("v!=" + ((Number) obj).longValue(), value2);
                    } else if(newF.equals("$in") && obj instanceof JsonArray){
                        JsonArray values = (JsonArray) obj;
                        for(Object value : values){
                            if(value2.equals(value)){
                                success = true;
                                break;
                            } else {
                                try {
                                    Pattern p = Pattern.compile((String) value);
                                    Matcher m = p.matcher((String) value2);
                                    if(m.matches()) {
                                        success = true;
                                        break;
                                    } else if(m.find()){
                                        success = true;
                                        break;
                                    }
                                } catch (Exception ignored){
                                }
                            }
                        }
                    } else if(newF.equals("$nin") && obj instanceof JsonArray){
                        success = true;
                        JsonArray values = (JsonArray) obj;
                        for(Object value : values){
                            if(value2.equals(value)){
                                success = false;
                                break;
                            } else {
                                try {
                                    Pattern p = Pattern.compile((String) value);
                                    Matcher m = p.matcher((String) value2);
                                    if(m.matches()) {
                                        success = false;
                                        break;
                                    } else if(m.find()){
                                        success = false;
                                        break;
                                    }
                                } catch (Exception ignored){
                                }
                            }
                        }
                    }
                }
            }
            return success;
        }
        return false;
    }

    private static int compareTo(Number n1, Number n2) {
        BigDecimal b1 = new BigDecimal(n1.doubleValue());
        BigDecimal b2 = new BigDecimal(n2.doubleValue());
        return b1.compareTo(b2);
    }
}
