package io.nebulosus.predicates;


import com.hazelcast.query.Predicate;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.regex.Pattern;


public class StringMatcherPredicate implements Serializable, Predicate {

    final private String key;
    final private String regex;
    final private Pattern pattern;

    public StringMatcherPredicate(String regex) {
        this(null, regex);
    }

    public StringMatcherPredicate(String key, String regex){
        this.key = key;
        this.regex = regex;
        this.pattern = Pattern.compile(regex);
    }

    @Override
    public boolean apply(Map.Entry entry) {
        try {
            if(key == null){
                return entry.getKey() instanceof String && ((String) entry.getKey()).matches(regex);
            }
            Object o = entry.getValue();
            Class<?> clazz = o.getClass();

            for(Field field : clazz.getDeclaredFields()) {
                if (field.getName().equals(key)) {
                    try {
                        Object c = field.get(o);
                        if(c != null){
                            if(c.toString().matches(regex)){
                                return true;
                            }
                        }
                    } catch (IllegalAccessException e) {
                    }
                }
            }
        } catch (Exception ignored){
            ignored.printStackTrace();
        }
        return false;
    }
}
