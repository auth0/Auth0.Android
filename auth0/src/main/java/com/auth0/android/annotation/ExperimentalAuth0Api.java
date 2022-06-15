package com.auth0.android.annotation;

import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PACKAGE;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.CLASS;

import androidx.annotation.RequiresOptIn;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * The APIs marked with this annotation are considered experimental
 * The API surface or design could change in future
 */
@Retention(CLASS)
@Target({TYPE, METHOD, CONSTRUCTOR, FIELD, PACKAGE})
@RequiresOptIn(level = RequiresOptIn.Level.WARNING)
public @interface ExperimentalAuth0Api {}
