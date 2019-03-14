var AppellationListItem = {
	props: ['appellation', 'sidebar', 'index'],
	template: `<li v-bind:class="{
						'list-group-item': true,
						'appellation-list-item': true,
						'appellation-selected': isSelected()
					}">
					
				<span class="pull-right text-muted btn-group">
					<a class="btn btn-xs" v-on:click="select">
						<span class="glyphicon glyphicon-hand-down"></span>
					</a>
					<a class="btn btn-xs" v-on:click="toggle">
						<span v-if="appellation.visible" class="glyphicon glyphicon glyphicon-eye-open"></span>
						<span v-else class="glyphicon glyphicon glyphicon-eye-close"></span>
					</a>
				</span>
				
				{{ label() }}
				<div class="text-warning">
					<input v-if="sidebar == 'submitAllAppellations'" type="checkbox" v-model="checked" aria-label="...">
					Created by <strong>{{ getCreatorName(appellation.createdBy) }}</strong> on {{ getFormattedDate(appellation.created) }}
				</div>
				</li>`,
	data: function () {
		return {
			checked: true
		}
	},
	watch: {
		checked: function () {
			if (this.checked == false) {
				this.$emit('removeAppellation', this.index);
			} else {
				this.$emit('addAppellation', this.appellation);
			}
		}
	},
	methods: {
		hide: function () {
			this.$emit("hideappellation", this.appellation);
		},
		show: function () {
			this.$emit("showappellation", this.appellation);
		},
		toggle: function () {
			if (this.appellation.visible) {
				this.hide();
			} else {
				this.show();
			}
		},
		isSelected: function () {
			return this.appellation.selected;
		},
		select: function () {
			this.$emit('selectappellation', this.appellation);
		},
		label: function () {
			if (this.appellation.interpretation) {
				return this.appellation.interpretation.label;
			} else if (this.appellation.dateRepresentation) {
				return this.appellation.dateRepresentation;
			}
		},
		getCreatorName: function (creator) {
			if (creator.id == USER_ID) {
				return 'you';
			} else {
				return creator.username;
			}
		},
		getFormattedDate: function (isodate) {
			var date = new Date(isodate);
			var monthNames = [
				"January", "February", "March",
				"April", "May", "June", "July",
				"August", "September", "October",
				"November", "December"
			];
			var minutes = String(date.getMinutes());
			if (minutes.length == 1) {
				minutes = '0' + minutes;
			}

			var day = date.getDate();
			var monthIndex = date.getMonth();
			var year = date.getFullYear();

			return day + ' ' + monthNames[monthIndex] + ', ' + year + ' at ' + date.getHours() + ':' + minutes;
		}

	}
}


AppellationList = {
	props: ['appellations', 'sidebar'],
	template: `
				<div>
					<div class="text-right ">
						<select  v-if="sidebar == 'submitAllAppellations'" v-model="selected_template" style="float: left;">
							<option value=0>Please select Relationship</option>
							<option v-for="template in templates" :value=template>{{ template.name }} - <span style="color: lightgrey;">{{ template.description }}</span></option>
						</select>
						<a v-if="allHidden()" v-on:click="showAll" class="btn">
							Show all
						</a>
						<a v-on:click="hideAll" class="btn">
							Hide all
						</a>
					</div>
					<div v-if="conceptLabel">
						<h5>Concept: {{ conceptLabel }}</h5>
					</div>
					<div v-else>
						<button v-if="sidebar == 'submitAllAppellations'"  @click="selectConcept()" class="btn btn-primary" >Select Concept</button>
					</div>
					<ul class="list-group appellation-list" style="max-height: 400px; overflow-y: scroll;">
						<appellation-list-item
							v-bind:sidebar="sidebar"
							v-on:hideappellation="hideAppellation"
							v-on:showappellation="showAppellation"
							v-on:selectappellation="selectAppellation"
							v-on:removeAppellation="removeAppellation($event)"
							v-on:addAppellation="addAppellation($event)"
							v-for="(appellation, index) in current_appellations"
							v-bind:appellation=appellation
							v-if="appellation != null"
							v-bind:index="index">
						</appellation-list-item>
					</ul>
				</div>
			   `,
	components: {
		'appellation-list-item': AppellationListItem,
	},
	data: function () {
		return {
			current_appellations: this.appellations,
			selected_template: null,
			templates: null,
			appellations_to_submit: []
		}
	},
	computed: {
		conceptLabel: function () {
			return store.getters.conceptLabel
		}
	},
	created: function () {
		this.getTemplates();
	},
	watch: {
		appellations: function (value) {
			// Replace an array prop wholesale doesn't seem to trigger a
			//  DOM update in the v-for binding, but a push() does; so we'll
			//  just push the appellations that aren't already in the array.
			var current_ids = this.current_appellations.map(function (elem) {
				return elem.id;
			});
			var self = this;
			this.appellations.forEach(function (elem) {
				if (current_ids.indexOf(elem.id) < 0) {
					self.current_appellations.push(elem);
				}
			});
		},
		selected_template: function () {
			store.commit("setTemplate", this.selected_template);
		},
	},
	methods: {
		/*************************************************
		 * Start Methods to create relationships to text *
		 *************************************************/
		selectConcept: function () {
			store.commit('triggerConcepts')
		},
		removeAppellation: function (index) {
			this.appellations_to_submit.splice(index, 1);
			store.commit('setAppellationsToSubmit', this.appellations_to_submit)
		},
		addAppellation: function (appellation) {
			this.appellations_to_submit.push(appellation);
			store.commit('setAppellationsToSubmit', this.appellations_to_submit)
		},
		getTemplates: function () {
			RelationTemplateResource.get_single_relation().then(response => {
				this.templates = response.body;
			}).catch(function (error) {
				console.log('Failed to get relationtemplates', error);
			});
		},
		getTemplateFields: function () {
			RelationTemplateResource.query({
				search: this.selected_template,
				format: "json",
				all: false
			}).then(function (response) {
				store.commit("setTemplate", response.body.templates[0]);
			}).catch(function (error) {
				console.log('Failed to get relationtemplates', error);
				self.searching = false;
			});
		},
		/***********************************************
		 * End Methods to create relationships to text *
		 ***********************************************/
		allHidden: function () {
			var ah = true;
			this.appellations.forEach(function (appellation) {
				if (appellation.visible) ah = false;
			});
			return ah;
		},
		hideAll: function () {
			this.$emit("hideallappellations");
		},
		showAll: function () {
			this.$emit("showallappellations");
		},
		hideAppellation: function (appellation) {
			this.$emit("hideappellation", appellation);
		},
		showAppellation: function (appellation) {
			this.$emit("showappellation", appellation);
		},
		selectAppellation: function (appellation) {
			this.$emit('selectappellation', appellation);
		},
	}
}